jQuery(function(){
    var filter = $("#filter");
    $("#commit").click(function(){
        var engine = new Bloodhound({
           name: 'commits',
           prefetch: {
               url: '/filter/commits?size=' + localStorage.getItem("issues")
           },
           datumTokenizer: function(data) {
               return Bloodhound.tokenizers.whitespace(data.description);
           },
           queryTokenizer: Bloodhound.tokenizers.whitespace
        });

        initialize_typeahead(engine, filter);

        $("#filter").typeahead(null, {
           displayKey: function(data) {
               return data.description;
           },
           source: engine.ttAdapter()
        }).on('typeahead:selected', function(event, datum) {
            localStorage.setItem("current_url", "/issues/commit/" + datum.commit);
            get_issues();
        });
    });

    $("#rule").click(function(){
        var engine = new Bloodhound({
           name: 'rules',
           prefetch: {
               url: '/filter/rules?size=' + localStorage.getItem("issues")
           },
           datumTokenizer: function(data) {
               return Bloodhound.tokenizers.whitespace(data);
           },
           queryTokenizer: Bloodhound.tokenizers.whitespace
        });

        initialize_typeahead(engine, filter);

        filter.typeahead(null, {
            displayKey: function(data) {
                return data;
            },
            source: engine.ttAdapter()
        }).on('typeahead:selected', function(event, datum) {
            localStorage.setItem("current_url", "/issues/rule/" + datum);
            get_issues();
        });
    });

    $("#reviewer").click(function(){
        var engine = new Bloodhound({
           name: 'reviewers',
           prefetch: {
               url: '/filter/reviewers?size=' + localStorage.getItem("issues")
           },
           datumTokenizer: function(data) {
               return Bloodhound.tokenizers.whitespace(data);
           },
           queryTokenizer: Bloodhound.tokenizers.whitespace
        });

        initialize_typeahead(engine, filter);
        filter.typeahead(null, {
            displayKey: function(data) {
                return data;
            },
            source: engine.ttAdapter()
        }).on('typeahead:selected', function(event, datum) {
            localStorage.setItem("current_url", "/issues/reviewer/" + datum);
            get_issues();
        });
    });

    $("#repo").click(function(){
        var engine = new Bloodhound({
           name: 'repos',
           prefetch: {
               url: '/filter/repos'
           },
           datumTokenizer: function(data) {
               return Bloodhound.tokenizers.whitespace(data);
           },
           queryTokenizer: Bloodhound.tokenizers.whitespace
        });

        initialize_typeahead(engine, filter);
        filter.typeahead(null, {
            displayKey: function(data) {
                return data;
            },
            source: engine.ttAdapter()
        }).on('typeahead:selected', function(event, datum) {
            localStorage.setItem("current_url", "/issues/repo/" + datum);
            get_issues();
        });
    });


    $("#reset-filter").click(function(){
       $("#filter").typeahead('destroy').off('typeahead:selected').val("");
       localStorage.setItem("current_url", "/issues/");
        get_issues();
    });

});

function initialize_typeahead(engine, filter) {
    engine.clearPrefetchCache();
    engine.initialize();

    filter.typeahead('destroy');
    filter.off('typeahead:selected');

}