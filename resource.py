from flask_restful import Resource,reqparse
from flask import Flask,abort,request
import config 
import helpers
class CheckHealth(Resource):
    def get(self):
        return {"status":"Hey Geek, Im Up and running "}

class SearchBooks(Resource):
    def get(self):
        args = request.args
        Url = "%s%s"%(config.EndpointURL,args.get('book'))
        responsestatus,response = helpers.GetResponsefromAPICall(Url)
        if responsestatus == 200:
            return response
        else :
            return abort(400, 'Unable to process the requests')


