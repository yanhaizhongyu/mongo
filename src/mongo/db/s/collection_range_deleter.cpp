/**
 *    Copyright (C) 2016 MongoDB Inc.
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

#define MONGO_LOG_DEFAULT_COMPONENT ::mongo::logger::LogComponent::kSharding

#include "mongo/platform/basic.h"

#include "mongo/db/s/collection_range_deleter.h"

#include <algorithm>
#include <utility>

#include "mongo/db/catalog/collection.h"
#include "mongo/db/client.h"
#include "mongo/db/db_raii.h"
#include "mongo/db/dbhelpers.h"
#include "mongo/db/exec/working_set_common.h"
#include "mongo/db/index/index_descriptor.h"
#include "mongo/db/keypattern.h"
#include "mongo/db/operation_context.h"
#include "mongo/db/query/internal_plans.h"
#include "mongo/db/query/query_knobs.h"
#include "mongo/db/query/query_planner.h"
#include "mongo/db/repl/repl_client_info.h"
#include "mongo/db/repl/replication_coordinator_global.h"
#include "mongo/db/s/collection_sharding_state.h"
#include "mongo/db/s/metadata_manager.h"
#include "mongo/db/s/sharding_state.h"
#include "mongo/db/service_context.h"
#include "mongo/db/write_concern.h"
#include "mongo/executor/task_executor.h"
#include "mongo/util/log.h"
#include "mongo/util/mongoutils/str.h"
#include "mongo/util/scopeguard.h"

namespace mongo {

class ChunkRange;

using CallbackArgs = executor::TaskExecutor::CallbackArgs;
using logger::LogComponent;

namespace {

const WriteConcernOptions kMajorityWriteConcern(WriteConcernOptions::kMajority,
                                                WriteConcernOptions::SyncMode::UNSET,
                                                Seconds(60));
}  // unnamed namespace

CollectionRangeDeleter::~CollectionRangeDeleter() {
    clear();  // notify anybody sleeping on orphan ranges
}

// This function runs in range deleter's task executor thread.
// call under a collection lock
bool CollectionRangeDeleter::cleanUpNextRange(OperationContext* opCtx,
                                              Collection* collection,
                                              BSONObj const& keyPattern,
                                              stdx::mutex* lock,
                                              int maxToDelete) {
    dassert(collection != nullptr);
    auto range = [lock, this]() -> boost::optional<ChunkRange> {
        stdx::lock_guard<stdx::mutex> lk(*lock);
        if (this->isEmpty()) {
            return boost::none;
        } else {
            return this->_orphans.front().range;
        }
    }();
    if (!range) {
        return false;
    }

    auto countWith = _doDeletion(opCtx, collection, keyPattern, *range, maxToDelete);
    if (!countWith.isOK() || countWith.getValue() == 0) {
        {
            stdx::lock_guard<stdx::mutex> scopedLock(*lock);
            _pop(countWith.getStatus());
        }
        return true;
    }

    // wait for replication
    WriteConcernResult wcResult;
    auto currentClientOpTime = repl::ReplClientInfo::forClient(opCtx->getClient()).getLastOp();
    Status status =
        waitForWriteConcern(opCtx, currentClientOpTime, kMajorityWriteConcern, &wcResult);
    if (!status.isOK()) {
        warning() << "Error when waiting for write concern after removing chunks in "
                  << collection->ns() << " : " << status.reason();
        {
            stdx::lock_guard<stdx::mutex> scopedLock(*lock);
            _pop(status);
        }
    }
    return true;
}

// This function runs in range deleter task executor thread..
// call under collection lock
StatusWith<int> CollectionRangeDeleter::_doDeletion(OperationContext* opCtx,
                                                    Collection* collection,
                                                    BSONObj const& keyPattern,
                                                    ChunkRange const& range,
                                                    int maxToDelete) {
    NamespaceString const& nss = collection->ns();

    // The IndexChunk has a keyPattern that may apply to more than one index - we need to
    // select the index and get the full index keyPattern here.
    auto catalog = collection->getIndexCatalog();
    const IndexDescriptor* idx = catalog->findShardKeyPrefixedIndex(opCtx, keyPattern, false);
    if (idx == NULL) {
        std::string msg = str::stream() << "Unable to find shard key index for "
                                        << keyPattern.toString() << " in " << nss.ns();
        log() << msg;
        return {ErrorCodes::InternalError, msg};
    }

    // Extend bounds to match the index we found
    KeyPattern indexKeyPattern(idx->keyPattern().getOwned());
    auto extend = [&](auto& key) {
        return Helpers::toKeyFormat(indexKeyPattern.extendRangeBound(key, false));
    };
    const BSONObj& min = extend(range.getMin());
    const BSONObj& max = extend(range.getMax());

    LOG(1) << "begin removal of " << min << " to " << max << " in " << nss.ns();

    auto indexName = idx->indexName();
    IndexDescriptor* descriptor = collection->getIndexCatalog()->findIndexByName(opCtx, indexName);
    if (!descriptor) {
        std::string msg = str::stream() << "shard key index with name " << indexName << " on '"
                                        << nss.ns() << "' was dropped";
        log() << msg;
        return {ErrorCodes::InternalError, msg};
    }

    int numDeleted = 0;
    do {
        auto bounds = BoundInclusion::kIncludeStartKeyOnly;
        auto manual = PlanExecutor::YIELD_MANUAL;
        auto forward = InternalPlanner::FORWARD;
        auto fetch = InternalPlanner::IXSCAN_FETCH;
        auto exec = InternalPlanner::indexScan(
            opCtx, collection, descriptor, min, max, bounds, manual, forward, fetch);
        RecordId rloc;
        BSONObj obj;
        PlanExecutor::ExecState state = exec->getNext(&obj, &rloc);
        if (state == PlanExecutor::IS_EOF) {
            break;
        }
        if (state == PlanExecutor::FAILURE || state == PlanExecutor::DEAD) {
            warning(LogComponent::kSharding)
                << PlanExecutor::statestr(state) << " - cursor error while trying to delete " << min
                << " to " << max << " in " << nss << ": " << WorkingSetCommon::toStatusString(obj)
                << ", stats: " << Explain::getWinningPlanStats(exec.get());
            break;
        }

        invariant(PlanExecutor::ADVANCED == state);
        WriteUnitOfWork wuow(opCtx);
        collection->deleteDocument(opCtx, rloc, nullptr, true);
        wuow.commit();
    } while (++numDeleted < maxToDelete);
    return numDeleted;
}

auto CollectionRangeDeleter::overlaps(ChunkRange const& range) -> DeleteNotification {
    // start search with newest entries by using reverse iterators
    auto it = find_if(_orphans.rbegin(), _orphans.rend(), [&](auto& cleanee) {
        return bool(cleanee.range.overlapWith(range));
    });
    return it != _orphans.rend() ? it->notification : DeleteNotification();
}

void CollectionRangeDeleter::add(ChunkRange const& range) {
    // We ignore the case of overlapping, or even equal, ranges.

    // Deleting overlapping ranges is similarly quick.
    _orphans.emplace_back(Deletion{ChunkRange(range.getMin().getOwned(), range.getMax().getOwned()),
                                   std::make_shared<Notification<Status>>()});
}

void CollectionRangeDeleter::append(BSONObjBuilder* builder) const {
    BSONArrayBuilder arr(builder->subarrayStart("rangesToClean"));
    for (auto const& entry : _orphans) {
        BSONObjBuilder obj;
        entry.range.append(&obj);
        arr.append(obj.done());
    }
    arr.done();
}

size_t CollectionRangeDeleter::size() const {
    return _orphans.size();
}

bool CollectionRangeDeleter::isEmpty() const {
    return _orphans.empty();
}

void CollectionRangeDeleter::clear() {
    std::for_each(_orphans.begin(), _orphans.end(), [](auto& range) {
        // Since deletion was not actually tried, we have no failures to report.
        if (!*(range.notification)) {
            range.notification->set(Status::OK());  // wake up anything waiting on it
        }
    });
    _orphans.clear();
}

void CollectionRangeDeleter::_pop(Status result) {
    _orphans.front().notification->set(result);  // wake up waitForClean
    _orphans.pop_front();
}

}  // namespace mongo
