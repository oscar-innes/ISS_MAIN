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
                "company_name", "members", "portfolio_balance", "investments", "advisor" ],
            "properties": {
                "company_name": {
                    "bsonType": "string",
                    "minLength": 1,
                    "maxLength": 100,
                    "description": "Username must be between 1 and 50 characters."
                },
                "members": {
                    "bsonType": "array",
                    "items": {
                        "bsonType": "string"
                    },
                    "description": "Group must be an array of strings."
                },
                "portfolio_balance": {
                    "bsonType": "double",
                    "description": "account balance for a client"
                },
                "investments": {
                    "bsonType": "array",
                    "items": {
                        "bsonType": "string"
                    },
                    "description": "Group must be an array of strings."
                },
                "advisor": {
                    "bsonType": "string",
                    "description": "Group must be an array of strings."
                },
            },
            "additionalProperties": True
        }
    }

    db.create_collection(coll_name, validator=validation_schema)
    print(f"Collection '{coll_name}' created with validation schema.")

if __name__ == '__main__':
    create_collection('CompanyPortfolios')