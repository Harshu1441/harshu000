from flask import Flask, request, jsonify
from pymongo import MongoClient
from datetime import datetime
from bson.objectid import ObjectId

app = Flask(__name__)

# MongoDB setup
client = MongoClient("mongodb://localhost:27017/")
db = client.firewall_app
rules_collection = db.rules
agents_collection = db.agents

# Register Agent
@app.route('/api/register', methods=['POST'])
def register_agent():
    data = request.json
    agent_name = data['name']
    agent_ip = data['ip']
    machine_id = data['machine_id']

    # Check if agent is already registered
    existing_agent = agents_collection.find_one({'machine_id': machine_id})
    if existing_agent:
        return jsonify({"message": "Agent already registered"}), 200

    # Register new agent
    agents_collection.insert_one({
        'name': agent_name,
        'ip': agent_ip,
        'machine_id': machine_id,
        'registered_at': datetime.now()
    })
    return jsonify({"message": "Agent registered successfully"}), 201

# Get Rules for an Agent
@app.route('/api/rules', methods=['GET'])
def get_rules():
    machine_id = request.headers.get('Machine-ID')
    if not machine_id:
        return jsonify({"error": "Machine-ID header is required"}), 400

    rules = list(rules_collection.find({'machine_ids': machine_id}, {'_id': 0}))
    return jsonify(rules), 200

# Add Rule
@app.route('/api/rules', methods=['POST'])
def add_rule():
    data = request.json
    rule = {
        'app_name': data['app_name'],
        'action': data['action'],
        'machine_ids': data['machine_ids'],  # List of agent machine IDs
        'ip_address': data.get('ip_address'),
        'domain': data.get('domain'),
    }
    rules_collection.insert_one(rule)
    return jsonify({"message": "Rule added successfully"}), 201

if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0', port=5500)
