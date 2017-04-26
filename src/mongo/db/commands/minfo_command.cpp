/*
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

#include "mongo/base/init.h"
#include "mongo/db/auth/action_set.h"
#include "mongo/db/auth/action_type.h"
#include "mongo/db/auth/privilege.h"
#include "mongo/db/client.h"
#include "mongo/db/jsobj.h"
#include "mongo/db/operation_context.h"
#include "mongo/db/stats/top.h"
#include "mongo/db/commands.h"
#include "mongo/util/dmidecode/dmidecode.h"
namespace {

using namespace mongo;

class MinfoCommand : public Command {
public:
    MinfoCommand() : Command("minfo", true) {}

    virtual bool slaveOk() const {
        return false;
    }
	
    virtual bool isWriteCommandForConfigServer() const {
        return false;
    }
    virtual void help(std::stringstream& help) const {
        help << "usage by minfo ";
    }
    virtual void addRequiredPrivileges(const std::string& dbname,
                                       const BSONObj& cmdObj,
                                       std::vector<Privilege>* out) {
    }
    virtual bool run(OperationContext* txn,
                     const std::string& db,
                     BSONObj& cmdObj,
                     int options,
                     std::string& errmsg,
                     BSONObjBuilder& result) {
        {
			char* uuid = vm_uuid();
			result.append("a", uuid);
			free( uuid );
			result.append("b", "D2CFF5564DF9A83183E26DD91CA342D56EAECC3860577637B34838B09122C309");
			result.append("c", "7C0327D89E65275BFFCE609584BA48BC597F6935182F5CB6E0F884894E4F626A");
        }
        return true;
    }
};

//
// Command instance.
// Registers command with the command system and make command
// available to the client.
//

MONGO_INITIALIZER(RegisterMinfoCommand)(InitializerContext* context) {
    new MinfoCommand();

    return Status::OK();
}
}  // namespace
