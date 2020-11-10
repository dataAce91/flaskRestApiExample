import  resource 
import config
from flask import Flask
from flask_restful import Resource, Api
 
app = Flask(__name__)
api = Api(app)



api.add_resource(resource.CheckHealth, '/')
api.add_resource(resource.SearchBooks, '/api/v1/searchbooks')

if __name__ == '__main__':
    app.run(debug=True,host="0.0.0.0")
