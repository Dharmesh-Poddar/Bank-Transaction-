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

		hashed_pw= bcrypt.hashpw(password.encode('utf8'),bcrypt.gensalt())

		users.insert({
			"Username":username,
			"password":hashed_pw,
			"Own": 0,
			"Debt": 0

			})

		    retJson={
		        "status": 200,
		        "msg": "You have registered successfully"

		    }

		    return jsonify(retJson)

def verifyPw(username, password):
	if not UserExist(username):
		return False 

	hashed_pw= users.find({
		"Username":username
		})[0]["Password"]

	if bcrypt.hashpw(password.encode('utf8'),hashed_pw)==hashed_pw:
		return True 
	else:
		return False 

def cashWithUser(username):
	cash = users.find({
		"Username":username
	})[0]["Own"]
     
    return cash  

def debtWithUser(username):
	debt= users.find({
		"Username":username 
		})[0]["Debt"]
    
    return debt 

def generateReturnDictionary(status,msg):
    retJson={
        "status": status,
        "msg": msg

    }
    return retJson


def verifyCredentials(username,password):
    if not UserExist(username):
        return generateReturnDictionary(301,"Invalid Username"),True 


    correct_pw =verifyPw(username, password)

    if not correct_pw:
    	return generateReturnDictionary(302,"Incorrect password"),True 

    return None, False 

def updateAccount(username,balance):
	users.update({
		"Username": username 

	},{
	    "$set":{
	        "Own": balance  

	    }

		})
def updateDebt(username, balance):
	users.update({
		"Username": username,

	},{
        "$set":{
            "Debt":balance
        }
	})
 
class Add(Resource):
	def post(self):
		postedData= request.get_json()

		username= postedData["username"]
		password = postedData["password"]
		money = postedData["amount"]

		retJson, error =verifyCredentials(username,pasword)

		if error:
			return jsonify(retJson)
		if money<=0:
			return jsonify(generateReturnDictionary(304,"The money amount entered must be greater than 0"))

		cash = cashWithUser(username)
		money-=1
		bank_cash= cashWithUser("BANK")
		updateAccount("BANK",bank_cash+1)
		updateAccount(username, cash+money)

        return jsonify(generateReturnDictionary(200,"Amount added successfully"))

class Transfer(Resource):
    def post(self):
        postedData= request.get_json()
        username= postedData["username"]
        password = postedData["password"]
        to = postedData["to"]
        money= postedData["amount"]

        retJson, error =verifyCredentials(username, password)

        if error:
            return jsonify(retJson)

        cash = cashWithUser(username)
        if cash<=0:
            return jsonify(generateReturnDictionary(304,"you are out of money "))

        if not UserExist(to):
        	return jsonify(generateReturnDictionary(301,"reciever username do not exist"))

        cash_from = cashWithUser(username)
        cash_to =cashWithUser(to)
        bank_cash= cashWithUser("BANK")

        updateAccount("BANK",bank_cash+1)
        updateAccount(to,cash_to+money-1)
        updateAccount(username, cash_from-money)
        
        return jsonify(generateReturnDictionary(200,"Amount transferred successfully"))

class Balance(Resource):
    def post(self):
    	postedData= request.get_json()
    	username= postedData["username"]
    	password= postedData["password"]

    	retJson, error= verifyCredentials(username,password)

    	if error:
    		return jsonify(retJson)

    	retJson= users.find({
    		"Username":username 

    		},{
    		    "Password": 0,
    		    "_id": 0
    		})[0]

    	    return jsonify(retJson)

class TakeLoan(Resource):
	def post(self):
		postedData=request.get_json()
		username= postedData["username"]
		password= postedData["password"]
		money= postedData["amount"]

		retJson,error =verifyCredentials(username, password)

		if error:
			return jsonify(retJson)

		cash= cashWithUser(username)
		debt = debtWithUser(username)
		updateAccount(username,cash+money)
		updateDebt(username,debt+money)

		return jsonify(generateReturnDictionary(200,"Loan added successfully"))

class PayLoan(Resource):
	def post(self):
		postedData= request.get_json()
		username= postedData["username"]
		password= postedData["password"]
		money= postedData["amount"]
         
        retJson,error =verifyCredentials(username, password)
         
        if error:
			return jsonify(retJson)

		cash= cashWithUser(username)

		if cash<money:
			return jsonify(generateReturnDictionary(303,"Not enough cash in your account"))

		debt = debtWithUser(username)

		updateAccount(username,cash-money)

        updateDebt(username, debt-money)

        return jsonify(generateReturnDictionary(200,"you have successfully paid your loan"))

api.add_resource()


