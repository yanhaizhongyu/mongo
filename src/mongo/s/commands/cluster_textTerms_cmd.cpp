/**
 *    Copyright (C) 2015 MongoDB Inc.
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

#include "mongo/platform/basic.h"

#include <vector>

#include "mongo/db/commands.h"
#include "mongo/s/cluster_explain.h"
#include "mongo/s/commands/cluster_commands_common.h"
#include "mongo/s/strategy.h"
#include "mongo/util/timer.h"

namespace mongo {

using std::string;
using std::vector;

namespace {

class CmdTextTerms : public Command {
public:
    CmdTextTerms() : Command("textTerms", false) {}

    virtual bool slaveOk() const {
        return true;
    }

    virtual bool adminOnly() const {
        return false;
    }

    virtual bool isWriteCommandForConfigServer() const {
        return false;
    }

    virtual void addRequiredPrivileges(const std::string& dbname,
                                       const BSONObj& cmdObj,
                                       std::vector<Privilege>* out) {
        ActionSet actions;
        actions.addAction(ActionType::find);
        out->push_back(Privilege(parseResourcePattern(dbname, cmdObj), actions));
    }

    virtual bool run(OperationContext* txn,
                     const std::string& dbname,
                     BSONObj& cmdObj,
                     int options,
                     std::string& errmsg,
                     BSONObjBuilder& result) {
						 
		const string collection = cmdObj.firstElement().valuestrsafe();
        const string ns = dbname + "." + collection;
		
		int nOption = cmdObj["option"].numberInt();


		BSONObj filter;
		
		vector<Strategy::CommandResult> results;
		Strategy::commandOp( txn, dbname, cmdObj, options, ns, filter, &results);

		std::set<std::string> setTerms;
		BSONArrayBuilder arr;

		for (vector<Strategy::CommandResult>::const_iterator i = results.begin(); i != results.end(); ++i) {
			BSONObj r = i->result;

			if (!r["ok"].trueValue()) {
				errmsg = str::stream() << "failure on shard: " << i->shardTargetId
					<< ": " << r["errmsg"];
				result.append("rawresult", r);
				return false;
			}

			if (r["results"].isABSONObj()) {
				BSONObjIterator j(r["results"].Obj());
				while (j.more()) {
					BSONElement e = j.next();
					if (nOption == 1)
					{
						arr.append(e);
					}
					else
					{
						setTerms.insert(e.str());
					}
				}
			}
		}

		if (nOption != 1)
		{
			for (std::set<std::string>::iterator i = setTerms.begin(); i != setTerms.end(); i++)
			{
				arr.append(*i);
			}
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

} cmdTextTerms;

}  // namespace
}  // namespace mongo
