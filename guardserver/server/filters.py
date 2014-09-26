from . import app
from authentication import requires_auth
from core.elastic_search_helpers import ElasticSearchHelpers
from core.datastore import DataStore, DataStoreException
from flask import request, make_response, escape
import arrow
import json


#helper function
class HashableDict(dict):
    def __hash__(self):
        return hash(tuple(sorted(self.items())))

def get_data_store():
    datastore = DataStore(host=app.config["ELASTIC_HOST"], port=app.config["ELASTIC_PORT"],
                          default_index=app.config["INDEX"], default_doctype=app.config["DOC_TYPE"])
    return datastore

@app.route("/filter/commits", methods=["GET"])
@requires_auth
def filter_by_commit():
    from_time = request.args.get("start_time", arrow.utcnow().replace(days=-7))
    to_time = request.args.get("end_time", arrow.utcnow())
    start = int(request.args.get("from", 0))
    end = int(request.args.get("size", 100))
    start_time = int(arrow.get(from_time).float_timestamp * 1000)
    end_time = int(arrow.get(to_time).float_timestamp * 1000)
    false_positive = request.args.get("false_positive", "false")
    sort_order = ElasticSearchHelpers.create_sort(True)
    time_filter = ElasticSearchHelpers.create_timestamp_filter(start_time, end_time)
    query_filter = ElasticSearchHelpers.create_query_string_filter("false_positive:" + false_positive)
    try:
        query = ElasticSearchHelpers.create_elasticsearch_filtered_query(filtered_query=query_filter,
                                                                         timestamp_filter=time_filter,
                                                                         sort_order=sort_order)
        datastore = get_data_store()
        params = dict(from_=start)
        params["size"] = end
        params["_source"] = "commit_id,commit_description"
        results = datastore.search(query=query, params=params)
        commits = set()
        for result in results["hits"]["hits"]:
            commit_and_description = HashableDict(commit=result["_source"]["commit_id"])
            commit_and_description["description"] = result["_source"]["commit_description"]
            commits.add(commit_and_description)
        # sets are not JSON serializable
        response = make_response(json.dumps(list(commits)))
        response.headers["Content-Type"] = "application/json"
        return response
    except DataStoreException:
        return "Failed to retrieve commits", 500

@app.route("/filter/reviewers", methods=["GET"])
@requires_auth
def filter_by_reviewer():
    from_time = request.args.get("start_time", arrow.utcnow().replace(days=-7))
    to_time = request.args.get("end_time", arrow.utcnow())
    start = int(request.args.get("from", 0))
    end = int(request.args.get("size", 100))
    start_time = int(arrow.get(from_time).float_timestamp * 1000)
    end_time = int(arrow.get(to_time).float_timestamp * 1000)
    false_positive = request.args.get("false_positive", "false")
    sort_order = ElasticSearchHelpers.create_sort(True)
    time_filter = ElasticSearchHelpers.create_timestamp_filter(start_time, end_time)
    query_filter = ElasticSearchHelpers.create_query_string_filter("false_positive:" + false_positive)
    try:
        query = ElasticSearchHelpers.create_elasticsearch_filtered_query(filtered_query=query_filter,
                                                                         timestamp_filter=time_filter,
                                                                         sort_order=sort_order)
        datastore = get_data_store()
        params = dict(from_=start)
        params["size"] = end
        params["_source"] = "last_reviewer"
        results = datastore.search(query=query, params=params)
        reviewers = set()
        for result in results["hits"]["hits"]:
            reviewers.add(result["_source"]["last_reviewer"])
        # sets are not JSON serializable
        response = make_response(json.dumps(list(reviewers)))
        response.headers["Content-Type"] = "application/json"
        return response
    except DataStoreException:
        return "Failed to retrieve commits", 500

@app.route("/filter/rules", methods=["GET"])
@requires_auth
def filter_by_rule():
    from_time = request.args.get("start_time", arrow.utcnow().replace(days=-7))
    to_time = request.args.get("end_time", arrow.utcnow())
    start = int(request.args.get("from", 0))
    end = int(request.args.get("size", 100))
    start_time = int(arrow.get(from_time).float_timestamp * 1000)
    end_time = int(arrow.get(to_time).float_timestamp * 1000)
    false_positive = request.args.get("false_positive", "false")
    sort_order = ElasticSearchHelpers.create_sort(True)
    time_filter = ElasticSearchHelpers.create_timestamp_filter(start_time, end_time)
    query_filter = ElasticSearchHelpers.create_query_string_filter("false_positive:" + false_positive)
    try:
        query = ElasticSearchHelpers.create_elasticsearch_filtered_query(filtered_query=query_filter,
                                                                         timestamp_filter=time_filter,
                                                                         sort_order=sort_order)
        datastore = get_data_store()
        params = dict(from_=start)
        params["size"] = end
        params["_source"] = "check_id"
        results = datastore.search(query=query, params=params)
        rules = set()
        for result in results["hits"]["hits"]:
            rule = result["_source"]["check_id"]
            rules .add(rule)
        # sets are not JSON serializable
        response = make_response(json.dumps(list(rules)))
        response.headers["Content-Type"] = "application/json"
        return response
    except DataStoreException:
        return "Failed to retrieve commits", 500

@app.route("/filter/repos", methods=["GET"])
@requires_auth
def filter_by_repo():
    try:
        query = ElasticSearchHelpers.create_elasticsearch_aggregate_query("repo_name")
        datastore = get_data_store()
        results = datastore.search(query=query)
        repos = set()
        for result in results["aggregations"]["my_aggregation"]["buckets"]:
            repo = result["key"]
            repos.add(repo)
        # sets are not JSON serializable
        response = make_response(json.dumps(list(repos)))
        response.headers["Content-Type"] = "application/json"
        return response
    except DataStoreException:
        return "Failed to retrieve commits", 500

