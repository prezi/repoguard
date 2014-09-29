#!/bin/bash

# Setup the static dependencies for Guard UI

# Create directories
mkdir static/css
mkdir static/js

# Download Bootstrap
curl https://maxcdn.bootstrapcdn.com/bootstrap/3.2.0/css/bootstrap.min.css > static/css/bootstrap.min.css
curl https://maxcdn.bootstrapcdn.com/bootstrap/3.2.0/js/bootstrap.min.js > static/js/bootstrap.min.js

# Download jQuery
curl https://ajax.googleapis.com/ajax/libs/jquery/1.11.1/jquery.min.js > static/js/jquery.min.js

# Get Prettify
curl https://google-code-prettify.googlecode.com/svn/loader/run_prettify.js > static/js/prettify.js

# Get datepicker
curl https://raw.githubusercontent.com/eternicode/bootstrap-datepicker/release/js/bootstrap-datepicker.js > static/js/bootstrap-datepicker.js
curl https://raw.githubusercontent.com/eternicode/bootstrap-datepicker/release/js/datepicker3.js > static/css/datepicker3.css
curl https://raw.githubusercontent.com/eternicode/bootstrap-datepicker/release/css/datepicker.css > static/css/datepicker.css

# Get Typeahead and Bloodhound
curl https://raw.githubusercontent.com/twitter/typeahead.js/master/dist/typeahead.bundle.min.js > static/js/typeahead.bundle.min.js
