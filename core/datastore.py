from elasticsearch import Elasticsearch, ElasticsearchException
import os
import sys
import hashlib


class DataStoreException (Exception):
    def __init__(self, error):
        self.error = error

    def __str__(self):
        return repr(self.error)


class DataStore:
    def __init__(self, host, port, username=None, password=None, use_ssl=False, default_index=None,
                 default_doctype=None):
        self.index = default_index
        self.doc_type = default_doctype
        if username and password:
            self.es_connection = Elasticsearch(host=host, port=port, http_auth=username + ":" + password,
                                               use_ssl=use_ssl)
        else:
            self.es_connection = Elasticsearch(host=host, port=port, use_ssl=use_ssl)
        if not self.es_connection.ping():
            raise DataStoreException("Connection to ElasticSearch failed.")
            self.es_connection = False

    def store(self, body):
        try:
            self.es_connection.create(body=body, id=hashlib.sha1(str(body)).hexdigest(), index=self.index,
                                      doc_type=self.doc_type)
        except ElasticsearchException, e:
            raise DataStoreException("Exception while storing data in Elastic Search: " + str(e))

    def search(self, query=None, params=None):
        try:
            if params:
                results = self.es_connection.search(body=query, index=self.index, doc_type=self.doc_type, params=params)
            else:
                results = self.es_connection.search(body=query, index=self.index, doc_type=self.doc_type)
            return results
        except ElasticsearchException, e:
            raise DataStoreException("Exception while searching data in Elastic Search: " + str(e))

    def get(self, issue_id):
        try:
            results = self.es_connection.get(index=self.index, doc_type=self.doc_type, id=issue_id)
            return results
        except ElasticsearchException, e:
            raise DataStoreException("Exception while retrieving data based on index ID: " + str(e))

    def update(self, index_id, doc):
        try:
            self.es_connection.update(body=doc, id=index_id, doc_type=self.doc_type, index=self.index)
        except ElasticsearchException, e:
            raise DataStoreException("Exception while updating data in Elastic Search: " + str(e))