from pymongo import MongoClient

def create_collection(coll_name):
    client = MongoClient('mongodb+srv://cryptoconnector:TheBigHammer123!!&@cluster0.vrpo6.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0')
    db = client.iss

    # Drop the collection if it already exists (optional, for testing)
    if coll_name in db.list_collection_names():
        db[coll_name].drop()

    validation_schema = {
        "$jsonSchema": {
            "bsonType": "object",
            "required": [
                "username", "password", "email", "country", "createdat", "postcode", "address", "fullname", "role", "salt"],
            "properties": {
                "username": {
                    "bsonType": "string",
                    "minLength": 1,
                    "maxLength": 50,
                    "description": "Username must be between 1 and 50 characters."
                },
                "password": {
                    "bsonType": "string",
                    "description": "Password must be a string."
                },
                "email": {
                    "bsonType": "string",
                    "description": "Email must be a valid string."
                },
                "postcode": {
                    "bsonType": "string",
                    "description": "Postcode must be a string."
                },
                "createdat": {
                    "bsonType": "string",
                    "description": "Timestamp of account creation."
                },
                "address": {
                    "bsonType": "string",
                    "description": "Address must be a string."
                },
                "country": {
                    "bsonType": "string",
                    "description": "Country must be a string."
                },
                "fullname": {
                    "bsonType": "string",
                    "description": "Full name must be a string."
                },
                "group": {
                    "bsonType": "array",
                    "items": {
                        "bsonType": "string"
                    },
                    "description": "Group must be an array of strings."
                },
                "role": {
                    "bsonType": "string",
                    "enum": ["Client", "Financial Advisor", "System Admin"],
                    "description": "Role must be one of the predefined values."
                },
                "salt": {
                    "bsonType": "string",
                    "description": "Address must be a string."
                },
                "token": {
                    "bsonType": "string",
                    "description": "Address must be a string."
                },
                "userhash": {
                    "bsonType": "string",
                    "description": "Address must be a string."
                },
            },
            "additionalProperties": True
        }
    }

    db.create_collection(coll_name, validator=validation_schema)
    print(f"Collection '{coll_name}' created with validation schema.")

if __name__ == '__main__':
    create_collection('ClientAccounts')


