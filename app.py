from flask import Flask,jsonify,request
from flask_restful import Api,Resource
from pymongo import MongoClient
import bcrypt

app=Flask(__name__)

api= Api(app)

client= MongoClient("mongodb://db:27017")
db= client.BankAPI
users= db["Users"]

def UserExist(username):
	if users.find({"Username":username}).count()==0:
		return False 
	else:
		return True 


class Register(Resource):
	def post(self):
		postedData=request.get_json()

		username= postedData["username"]
		password= postedData["password"]


		if UserExist(username):
			return retJson{
			    status: '301',
			    "msg": "username already exist"
			}
			return jsonify(retJson)
			