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

#include <string>
#include <vector>
#include <set>
#include <list>

#include "mongo/db/commands.h"
#include "mongo/db/fts/fts_util.h"
#include "mongo/util/mongoutils/str.h"
#include "mongo/util/timer.h"
#include "mongo/db/index/fts_access_method.h"
#include "mongo/db/db.h"
#include "mongo/db/db_raii.h"

namespace mongo {

	namespace fts {

		using namespace mongoutils;
		using std::string;
		using std::stringstream;
		using std::vector;
		using std::set;

		/* select textTerms(*) */
		class CmdTextTerms : public Command {
		public:
			OperationContext* _txn;
			virtual bool isWriteCommandForConfigServer() const { return false; }

			CmdTextTerms() : Command("textTerms") { }
			virtual bool logTheOp() { return false; }
			virtual bool slaveOk() const { return true; }
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

			bool GetTerms2(const FTSAccessMethod* fam, string& errmsg, std::set<std::string> &textTerms, bool isForward)
			{
				std::unique_ptr<SortedDataInterface::Cursor> cursor = fam->newCursor(_txn, isForward);
				boost::optional<IndexKeyEntry> kv = cursor->seek(BSONObj(), true, SortedDataInterface::Cursor::kWantKey);
				
				while (kv)
				{
					BSONObj obj = kv->key;
					BSONObjIterator keyDataIt(obj);
					if (keyDataIt.more()) {
						BSONElement keyDataElt = keyDataIt.next();
						textTerms.insert(keyDataElt.String());
					}						

					kv = cursor->next(SortedDataInterface::Cursor::kWantKey);
				}
				return true;				
			}

			virtual bool run(OperationContext* txn, const string& dbname, BSONObj& cmdObj, int, string& errmsg, BSONObjBuilder& result) {
				_txn = txn;

				string ns = dbname + "." + cmdObj.firstElement().String();

				AutoGetCollectionForRead ctx(txn, ns);
				Collection* collection = ctx.getCollection();

				if (NULL == collection) {
					errmsg = "ns missing";
					return false;
				}

				//
				vector<IndexDescriptor*> idxMatches;
				collection->getIndexCatalog()->findIndexByType(txn, IndexNames::TEXT, idxMatches, false);
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
					static_cast<FTSAccessMethod*>(collection->getIndexCatalog()->getIndex(index));
				invariant(fam);
	
				std::set<std::string> textTerms;
				BSONArrayBuilder arr;

				GetTerms2(fam, errmsg, textTerms, false);

				if (textTerms.empty())
				{
					GetTerms2(fam, errmsg, textTerms, true);
				}

				for (auto i = textTerms.begin(); i != textTerms.end(); i++)
				{
					arr.append(*i);
				}

				long long nn = arr.arrSize();
				if (nn == 0) {
					result.appendBool("missing", true);
				}
				else{
					result.appendArray("results", arr.arr());
				}
				result.append("n", (double)nn);
				return true;
			}
		}CmdTextTerms;
	}
}
