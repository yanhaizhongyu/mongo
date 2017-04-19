// fts_command.h

/**
*    Copyright (C) 2012 10gen Inc.
*
*    This program is free software: you can redistribute it and/or  modify
*    it under the terms of the GNU Affero General Public License, version 3,
*    as published by the Free Software Foundation.
*
*    This program is distributed in the hope that it will be useful,
*    but WITHOUT ANY WARRANTY; without even the implied warranty of
*    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
*    GNU Affero General Public License for more details.
*
*    You should have received a copy of the GNU Affero General Public License
*    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*
*    As a special exception, the copyright holders give permission to link the
*    code of portions of this program with the OpenSSL library under certain
*    conditions as described in each individual source file and distribute
*    linked combinations including the program with the OpenSSL library. You
*    must comply with the GNU Affero General Public License in all respects for
*    all of the code used other than as permitted herein. If you modify file(s)
*    with this exception, you may extend this exception to your version of the
*    file(s), but you are not obligated to do so. If you do not wish to do so,
*    delete this exception statement from your version. If you delete this
*    exception statement from all source files in the program, then also delete
*    it in the license file.
*/

#define MONGO_LOG_DEFAULT_COMPONENT ::mongo::logger::LogComponent::kCommand

#include <string>
#include <vector>
#include <set>
#include <list>

#include "mongo/base/string_data.h"
#include "mongo/db/commands.h"
#include "mongo/db/fts/fts_util.h"
#include "mongo/util/mongoutils/str.h"
#include "mongo/util/timer.h"
#include "mongo/db/catalog/database.h"
#include "mongo/db/ops/insert.h"
#include "mongo/db/catalog/database_holder.h"
#include "mongo/db/index/fts_access_method.h"
#include "mongo/db/db.h"
#include "mongo/db/db_raii.h"
#include "mongo/db/dbhelpers.h"
#include "mongo/db/catalog/index_create.h"
#include "mongo/util/log.h"
#include "mongo/db/concurrency/write_conflict_exception.h"
#include "mongo/db/repl/replication_coordinator_global.h"
#include "mongo/db/repl/repl_client_info.h"
#include "mongo/db/namespace_string.h"
#include "mongo/db/dbdirectclient.h"
#include "mongo/util/scopeguard.h"
#include "mongo/stdx/mutex.h"
//
// Very likely there are #include's which are not needed above 
//             
namespace mongo {

    namespace fts {

        using namespace mongoutils;
        using std::string;
        using std::stringstream;
        using std::vector;
        using std::set;

        /* select textTerms(*) */
        class CmdTextTermBuild2 : public Command {
        public:
            /****************************************************/
            // Command is global instance                        /
            // Do NOT share OperationContext across run() calls! /
            /****************************************************/
            //OperationContext* _txn;
            virtual bool isWriteCommandForConfigServer() const { return false; }
            std::timed_mutex Lurch;

            CmdTextTermBuild2() : Command("textTermBuild") {
               // log() << "WOW THE NEW CmdtextTermBuild's are in!!!!!!!! " << std::endl;
            }
            virtual bool logTheOp() { return true; }
            virtual bool slaveOk() const { return false; }
            virtual bool slaveOverrideOk() const { return true; }
            virtual bool maintenanceOk() const { return false; }
            virtual bool adminOnly() const { return false; }
            virtual void help(stringstream& help) const { help << "text terms in collection"; }
            virtual void addRequiredPrivileges(const std::string& dbname,
                const BSONObj& cmdObj,
                std::vector<Privilege>* out) {
                ActionSet actions;
                actions.addAction(ActionType::find);
                out->push_back(Privilege(parseResourcePattern(dbname, cmdObj), actions));
            }

            bool InsertTerms(OperationContext* txn, const std::string& dbName, Collection* collTerm, NamespaceString nsTerms, NamespaceString nsSourceTerms, const FTSAccessMethod* fam, bool isForward)
            {
                log() << "InsertTerms called on textTermBuild " << nsTerms.ns() << " " << nsSourceTerms.ns();
                std::unique_ptr<ScopedTransaction> scopedXact(new ScopedTransaction(txn, MODE_IX));
                std::unique_ptr<Lock::CollectionLock> collLock = stdx::make_unique<Lock::CollectionLock>(txn->lockState(), nsTerms.ns(), MODE_IX);
                std::unique_ptr<Lock::CollectionLock> csollLock = stdx::make_unique<Lock::CollectionLock>(txn->lockState(), nsSourceTerms.ns(), MODE_IS);
                std::unique_ptr<SortedDataInterface::Cursor> cursor = fam->newCursor(txn, isForward);
                boost::optional<IndexKeyEntry> kv = cursor->seek(BSONObj(), true, SortedDataInterface::Cursor::kWantKey);
                bool bReturn = false;
                int nCount = 0;
                int nIndex = 0;
                time_t lastLog(0);
                set<string > setTerms;

                while (kv)
                {
                    if (nCount % 128 == 127) {
                        time_t now = time(0);
                        if (now - lastLog >= 60) {
                            // report progress
                            if (lastLog)
                                log() << "textTermBuild InsertTerms " << dbName << ' ' << nCount << std::endl;
                            lastLog = now;
                        }
                        txn->checkForInterrupt();
                        scopedXact.reset();
                        collLock.reset();
                        CurOp::get(txn)->yielded();
                        scopedXact.reset(new ScopedTransaction(txn, MODE_IX));
                        collLock.reset(new Lock::CollectionLock(txn->lockState(), nsTerms.ns(), MODE_IX));
                    }
                    BSONObj obj = kv->key;
                    BSONObjIterator keyDataIt(obj);
                    if (keyDataIt.more()) {
                        bReturn = true;
                        BSONElement keyDataElt = keyDataIt.next();
                        string strTerm = keyDataElt.String();
                        if (setTerms.find(strTerm) == setTerms.end())
                        {
                            setTerms.insert(strTerm);

                            MONGO_WRITE_CONFLICT_RETRY_LOOP_BEGIN{
                                txn->checkForInterrupt();
                                WriteUnitOfWork wunit(txn);
                                Status status = collTerm->insertDocument(txn, BSON("_id" << nIndex << "term" << strTerm), true);
                                //log() << "textTermBuild:" << status.toString();
                                nCount++;
                                nIndex++;
                                if (!status.isOK()) {
                                    error() << "error: exception textTermBuild InsertTerms object in " << "PUT COLLECTION NAME HERE" << ' '
                                        << status << " term:" << strTerm;
                                }
                                uassertStatusOK(status);
                                wunit.commit();
                            }
                            MONGO_WRITE_CONFLICT_RETRY_LOOP_END(txn, "textTermBuild InsertTerms", "PUT COLLECTION NAME HERE");
                        }
                    }
                    kv = cursor->next(SortedDataInterface::Cursor::kWantKey);
                }
                // need more work on bReturn here... problems are just logged above
                return bReturn;
            }


            virtual bool run(OperationContext* txn, const string& dbname, BSONObj& cmdObj, int, string& errmsg, BSONObjBuilder& result) {

                /*********************************
                / command instance is singleton! /
                / cannot share OperationContext  /
                *********************************/
                //_txn = txn;

                string targetColl = cmdObj.firstElement().String();
                string ns = dbname + "." + cmdObj.firstElement().String();    // test.Foo
                string nsTerm = ns + "_Terms";  // test.Foo_Terms
                string cTermNew = cmdObj.firstElement().String() + "_Terms.new";  //Foo_Terms.new
                string nsTermNew = dbname + "." + cTermNew;  // test.Foo_Terms.new

                stdx::unique_lock<std::timed_mutex> lock(Lurch, std::defer_lock);  // NOLINT

                /*
                * You guy's can test out try_lock_for() if you want
                * seems that it would be ok for a thread to wait a little to let
                * a currently running request to complete
                */
                //auto gotLock = lock.try_lock_for(std::chrono::milliseconds(10));
                auto gotLock = lock.try_lock();

                if (!gotLock) {
                    error() << "Unable to lock Lurch:" << targetColl << std::endl;
                    errmsg = "Unable to acquire termBuildCommand lock, another termBuildCommand may be in process, quit ";
                    return appendCommandStatus(
                        result,
                        Status(ErrorCodes::UnknownError,
                        str::stream() << errmsg
                        << targetColl));

                }
                else {
                    log() << "termBuildCommand Lock acquired for " << targetColl << std::endl;
                }

                NamespaceString nsTargetColl(dbname, targetColl);
                NamespaceString nsTermsColl(dbname, targetColl + "_Terms");
                NamespaceString nsTermsCollNew(dbname, targetColl + "_Terms.new");

                // some security?        
                Status status = userAllowedWriteNS(nsTermsColl);
                if (!status.isOK()) {
                    return appendCommandStatus(result, status);
                }

                // some availability?
                if (!repl::getGlobalReplicationCoordinator()->canAcceptWritesFor(nsTermsCollNew)) {
                    return appendCommandStatus(
                        result,
                        Status(ErrorCodes::NotMaster,
                        str::stream() << "textTermBuild called, but not PRIMARY: " << nsTermsCollNew.ns()));

                }

                // 1. drop <coll>_Terms.new
                // 2. create <coll>_Terms.new
                // 3. createIndex <coll>_Terms.new { "term" : 1 }
                ScopedTransaction transaction(txn, MODE_X);
                Collection* collTarget = nullptr;
                Collection* collTermsCollNew = nullptr;
                //need to release the DB level lock to allow concurrent process after create new term collection
                {
                    Lock::DBLock dbLock(txn->lockState(), nsTermsCollNew.db(), MODE_X);
                    Lock::CollectionLock colLock(txn->lockState(), nsTermsCollNew.ns(), MODE_X);

                    Database* db = dbHolder().get(txn, nsTermsCollNew.db());
                    if (!db) {
                        log() << "Did not get db holder, try again..." << std::endl;
                        db = dbHolder().openDb(txn, nsTermsCollNew.db());
                    }


                    collTermsCollNew = db->getCollection(nsTermsCollNew.ns());
                    // the <coll>_Terms.new should never be there! it's always renamed at 
                    // the end of this command
                    if (collTermsCollNew)
                    {
                        log() << nsTermNew << " collection exists,  might be caused by unexpeted power off, drop  and continue anyway " << std::endl;
                        MONGO_WRITE_CONFLICT_RETRY_LOOP_BEGIN{
                            WriteUnitOfWork wunit(txn);
                            Status ds = db->dropCollection(txn, nsTermNew);
                            if (ds.isOK()) {
                                log() << "textTermBuild dropped " << nsTermNew << std::endl;
                                collTermsCollNew = nullptr;
                            }
                            else {
                                result.append("error", ds.reason());
                                errmsg = ds.reason();
                                error() << "textTermBuild drop error:" << ds.reason() << std::endl;
                                return false;
                            }
                            wunit.commit();
                        }
                        MONGO_WRITE_CONFLICT_RETRY_LOOP_END(txn, "textTermBuild", nsTermsCollNew.ns());
                    }
                    if (!collTermsCollNew) {
                        //std::unique_ptr<Lock::CollectionLock> collLock = stdx::make_unique<Lock::CollectionLock>(txn->lockState(), nsTermsCollNew.ns(), MODE_X);
                        //if (!txn->lockState()->isCollectionLockedForMode(nsTermsCollNew.coll(), MODE_X)) {
                        //    log() << "not locked... I just can't go on..." << nsTermsCollNew.coll();
                        //    //return false;
                        //}
                        MONGO_WRITE_CONFLICT_RETRY_LOOP_BEGIN{
                            WriteUnitOfWork wunit(txn);
                            collTermsCollNew = db->createCollection(txn, nsTermsCollNew.ns(), CollectionOptions());
                            invariant(collTermsCollNew);
                            collTermsCollNew->getIndexCatalog()->createIndexOnEmptyCollection(txn, BSON("terms" << 1));
                            wunit.commit();
                        }
                        MONGO_WRITE_CONFLICT_RETRY_LOOP_END(txn, "create:" + nsTermNew, nsTermsCollNew.ns());
                    }                   
                }

				
				
                // 4. find text index in <coll>
                // 5. get FTSAccessMethod
                // note that someone may hijack the _new terms collection by just delete it while we operating on it.
				// since we cannot use DB MODE_X lock here.
                Lock::DBLock dbLock(txn->lockState(), nsTermsCollNew.db(), MODE_IX);

                Database* db = dbHolder().get(txn, nsTermsCollNew.db());
                if (!db) {
                    log() << "Did not get db holder, try again..." << std::endl;
                    db = dbHolder().openDb(txn, nsTermsCollNew.db());
                }


                collTarget = db->getCollection(nsTargetColl.ns());
                if (!collTarget) {
                    log() << "textTermBuild collection " << nsTargetColl.ns() << " does not exist" << std::endl;
                    return appendCommandStatus(
                        result,
                        Status(ErrorCodes::UnknownError,
                        str::stream() << "textTermBuild collection " << nsTargetColl.ns() << " does not exist"));
                }
                vector<IndexDescriptor*> idxMatches;

                collTarget->getIndexCatalog()->findIndexByType(txn, IndexNames::TEXT, idxMatches, false);
                if (idxMatches.empty()) {
                    errmsg = "text index required for textTerms command";
                    return false;
                }
                if (idxMatches.size() > 1) {
                    errmsg = "more than one text index found for textTerms command";
                    return false;
                }
                invariant(idxMatches.size() == 1);
                IndexDescriptor* index = idxMatches[0];
                const FTSAccessMethod* fam =
                    static_cast<FTSAccessMethod*>(collTarget->getIndexCatalog()->getIndex(index));
                invariant(fam);

                if (!repl::getGlobalReplicationCoordinator()->canAcceptWritesFor(nsTargetColl)) {
                    return appendCommandStatus(
                        result,
                        Status(ErrorCodes::NotMaster,
                        str::stream() << "Not primary while creating background indexes in "
                        << nsTargetColl.ns()));
                }
                // 6. call InsertTerms into <coll>_Terms.new
                InsertTerms(txn, dbname, collTermsCollNew, nsTermsCollNew, nsTargetColl, fam, true);

                // 7. Drop <coll>_Terms
                // 8. Rename <coll>_Terms -> <coll>_Terms.new
                MONGO_WRITE_CONFLICT_RETRY_LOOP_BEGIN{
                    Lock::DBLock dbLock2(txn->lockState(), nsTermsColl.db(), MODE_X);
                    WriteUnitOfWork wunit(txn);
                    log() << "textTermBuild rename start from:" << nsTermNew << " to:" << nsTerm << std::endl;
                    log() << "textTermBuild rename try drop:" << nsTerm << std::endl;
                    Status ds = db->dropCollection(txn, nsTerm);
                    if (ds.isOK()) {
                        log() << "textTermBuild rename dropped " << nsTerm << std::endl;
                    }
                    else {
                        result.append("error", ds.reason());
                        errmsg = ds.reason();
                        error() << "textTermBuild drop error:" << ds.reason() << std::endl;
                        return false;
                    }
                    Status status = db->renameCollection(txn, nsTermNew, nsTerm, true /* ?stayTemp? this will drop if exists?*/);

                    log() << "textTermBuild rename done" << std::endl;
                    if (!status.isOK()) {
                        result.append("error", status.reason());
                        errmsg = status.reason();
                        error() << "textTermBuild rename error:" << status.reason() << std::endl;
                        return false;
                    }
                    wunit.commit();
                }
                MONGO_WRITE_CONFLICT_RETRY_LOOP_END(txn, "textTermBuild", nsTermsColl.ns());

                lock.unlock();  // release Lurch
                log() << "Release lock for " << nsTargetColl.ns() << std::endl;
                log() << "textTermBuild done " << targetColl << std::endl;
                result.append("ok", 1);
                return true;
            }
        }CmdtextTermBuild;
    }
}
