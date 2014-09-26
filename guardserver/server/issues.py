from . import app
from authentication import requires_auth
from core.elastic_search_helpers import ElasticSearchHelpers
from core.datastore import DataStore, DataStoreException
from core.git_repo_querier import GitRepoQuerier
from flask import request, make_response, escape
import arrow
import json
import urllib

def get_data_store():
    datastore = DataStore(host=app.config["ELASTIC_HOST"], port=app.config["ELASTIC_PORT"],
                          default_index=app.config["INDEX"], default_doctype=app.config["DOC_TYPE"])
    return datastore

@app.route('/issues/', methods=['GET'])
@requires_auth
# Takes the time in days as an argument
def get_issues():
    from_time = request.args.get("start_time")
    to_time = request.args.get("end_time")
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
        results = datastore.search(query=query, params=params)
        issues = make_issues_object(results["hits"]["hits"], results["hits"]["total"])
        response = make_response(json.dumps(issues))
        response.headers["Content-Type"] = "application/json"
        return response
    except DataStoreException:
        return "Failed to retrieve issues", 500

@app.route('/issue/<string:issue_id>')
@requires_auth
def get_issue(issue_id):
    try:
        datastore = get_data_store()
        result = datastore.get(issue_id=issue_id)
        response = make_response(json.dumps(result))
        response.headers["Content-Type"] = "application/json"
        return response
    except DataStoreException:
        return "Failed to retrieve issues", 500

@app.route('/issues/commit/<string:commit_id>')
@requires_auth
def get_issues_by_commit(commit_id):
    start = int(request.args.get("from", 0))
    end = int(request.args.get("size", 100))
    query = ElasticSearchHelpers.create_elasticsearch_simple_query(search_parameter="commit_id",
                                                                   search_string=commit_id)
    query["from_"] = start
    query["size"] = end
    try:
        datastore = get_data_store()
        results = datastore.search(params=query)
        issues = make_issues_object(results["hits"]["hits"], results["hits"]["total"])
        response = make_response(json.dumps(issues))
        response.headers["Content-Type"] = "application/json"
        return response
    except DataStoreException:
        return "Failed to retrieve issues by commit", 500

@app.route('/issues/rule/<string:check_id>')
@requires_auth
def get_issues_by_rule(check_id):
    start = int(request.args.get("from", 0))
    end = int(request.args.get("size", 100))
    query = ElasticSearchHelpers.create_elasticsearch_simple_query(search_parameter="check_id",
                                                                   search_string=urllib.quote_plus(check_id))
    query["from_"] = start
    query["size"] = end
    try:
        datastore = get_data_store()
        results = datastore.search(params=query)
        issues = make_issues_object(results["hits"]["hits"], results["hits"]["total"])
        response = make_response(json.dumps(issues))
        response.headers["Content-Type"] = "application/json"
        return response
    except DataStoreException:
        return "Failed to retrieve issues by rule", 500

@app.route('/issues/reviewer/<string:reviewer>')
@requires_auth
def get_issues_by_reviewer(reviewer):
    start = int(request.args.get("from", 0))
    end = int(request.args.get("size", 100))
    query = ElasticSearchHelpers.create_elasticsearch_simple_query(search_parameter="last_reviewer",
                                                                   search_string=urllib.quote_plus(reviewer))
    query["from_"] = start
    query["size"] = end
    try:
        datastore = get_data_store()
        results = datastore.search(params=query)
        issues = make_issues_object(results["hits"]["hits"], results["hits"]["total"])
        response = make_response(json.dumps(issues))
        response.headers["Content-Type"] = "application/json"
        return response
    except DataStoreException:
        return "Failed to retrieve issues by reviewer", 500

@app.route('/issues/repo/<string:repo>')
@requires_auth
def get_issues_by_repo(repo):
    start = int(request.args.get("from", 0))
    end = int(request.args.get("size", 100))
    query = ElasticSearchHelpers.create_elasticsearch_simple_query(search_parameter="repo_name",
                                                                   search_string=urllib.quote_plus(repo))
    query["from_"] = start
    query["size"] = end
    try:
        datastore = get_data_store()
        results = datastore.search(params=query)
        issues = make_issues_object(results["hits"]["hits"], results["hits"]["total"])
        response = make_response(json.dumps(issues))
        response.headers["Content-Type"] = "application/json"
        return response
    except DataStoreException:
        return "Failed to retrieve issues by reviewer", 500

@app.route('/issue/get_contents/<string:commit_id>')
@requires_auth
def get_file_contents_by_commit(commit_id):
    file_path = request.args.get("file_path")
    repo = request.args.get("repo")
    if not file_path or not repo:
        return "File Path/Repository is required", 400
    github_querier = GitRepoQuerier(app.config["ORG_NAME"], app.config["GITHUB_TOKEN"])
    file_contents = github_querier.get_file_contents(repo=repo, filename=file_path, commit_id=commit_id)
    response = make_response(file_contents)
    response.headers["Content-Type"] = "text/plain"
    return response

@app.route('/issue/status/<string:issue_id>', methods=['PUT'])
def update_issue_state(issue_id):
    if "status" in request.form and "current_user" in request.form:
        changed_status = request.form["status"]
        current_user = request.form["current_user"]
    else:
        return "Changed Status Value Required.", 400

    doc = ElasticSearchHelpers.create_elasticsearch_doc({"false_positive": changed_status,
                                                         "last_reviewer": current_user})
    try:
        datastore = get_data_store()
        datastore.update(index_id=issue_id, doc=doc)
        response = make_response("Completed")
        return response
    except DataStore, e:
        return "Failed to update issue status", 500


def make_issues_object(results,total):
    issues = dict(total=total)
    issues["issues"] = []
    for result in results:
        issue = dict(id=result["_id"])
        issue["_source"] = result["_source"]
        issues["issues"].append(issue)
    return issues

