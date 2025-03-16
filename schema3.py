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
                "initiated_by", "approved_by", "approved", "amount", "sender_group", "timestamp", "signature"],
            "properties": {
                "initiated_by": {
                    "bsonType": "string",
                    "minLength": 1,
                    "maxLength": 50,
                    "description": "Username must be between 1 and 50 characters."
                },
                "approved_by": {
                    "bsonType": "string",
                    "minLength": 1,
                    "maxLength": 100,
                    "description": "Username must be between 1 and 50 characters."
                },
                "approved":{
                    "bsonType": "bool",
                    "description": "Confirms transaction is completed by an advisor"
                },
                "amount": {
                    "bsonType": "string",
                    "description": "account balance for a client"
                },
                "sender_group": {
                    "bsonType": "string",
                    "description": "Group must be an array of strings."
                },
                "timestamp": {
                    "bsonType": "string",
                    "description": "Timestamp of account creation."
                },
                "signature": {
                    "bsonType": "string",
                    "description": "Timestamp of account creation."
                },
            },
            "additionalProperties": True
        }
    }

    db.create_collection(coll_name, validator=validation_schema)
    print(f"Collection '{coll_name}' created with validation schema.")

if __name__ == '__main__':
    create_collection('Transactions')