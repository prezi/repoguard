class ElasticSearchHelpers:
    def __init__(self):
        pass


    # These methods help create a filtered elastic search query:
    # see http://www.elasticsearch.org/guide/en/elasticsearch/reference/current/query-dsl-filtered-query.html#_multiple_filters


    @staticmethod
    def create_query_string_filter(lucene_query):
        filtered_query_string = {
            "bool": {
                "should": [
                    {
                        "query_string": {
                            "query": lucene_query
                        }
                    }
                ]
            }
        }
        return filtered_query_string


    @staticmethod
    def create_timestamp_filter(from_date, to_date):
        filtered_timestamp = {
            "bool": {
                "must": [
                    {
                        "range": {
                            "@timestamp": {
                                "from": from_date,
                                "to": to_date
                            }
                        }
                    }
                ]
            }
        }
        return filtered_timestamp


    @staticmethod
    def create_sort(order):
        if order:
            sort_order = "desc"
        else:
            sort_order = "asc"
        sort_order_query = [
            {
                "@timestamp": {
                    "order": sort_order
                }
            }
        ]
        return sort_order_query


    @staticmethod
    def create_elasticsearch_filtered_query(timestamp_filter, sort_order, filtered_query=None):
        filtered_query_params = dict(filter=timestamp_filter)
        if filtered_query:
            filtered_query_params["query"] = filtered_query
        filtered_query_dict = dict(filtered=filtered_query_params)
        query = dict(query=filtered_query_dict, sort=sort_order)
        print query
        return query

    @staticmethod
    def create_elasticsearch_simple_query(search_parameter, search_string):
        return dict(q=search_parameter + ":" + search_string)

    @staticmethod
    def create_elasticsearch_aggregate_query(field_name):
        field_dict = dict(field=field_name)
        terms_dict = dict(terms=field_dict)
        agg_name_dict = dict(my_aggregation=terms_dict)
        aggs = dict(aggs=agg_name_dict)
        return aggs

    @staticmethod
    def create_elasticsearch_doc(changed_values):
        return dict(doc=changed_values)
