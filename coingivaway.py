from flask import Flask, render_template, jsonify

app = Flask(__name__)

central_wallet_address = '0x6Fd50a74fFf5D3205b9Ad296122FEb1466c68F28'
central_wallet_private_key = '86014fa7a3efecfb521600b55616e4aca9ad754de7772e4ea6a9c93da7889602'

contract_address = "0x978DE00A564b87AD7f53ba3670de47dB51E402E0"
contract_abi = [
    {
        "constant": False,
        "inputs": [
            {
                "name": "_to",
                "type": "address"
            },
            {
                "name": "_value",
                "type": "uint256"
            }
        ],
        "name": "transfer",
        "outputs": [
            {
                "name": "",
                "type": "bool"
            }
        ],
        "type": "function"
    }
]

@app.route('/')
def connect_wallet():
    return render_template('connect_wallet.html')

@app.route('/get_wallet_info')
def get_wallet_info():
    return jsonify({
        'centralWalletAddress': central_wallet_address,
        'contractAddress': contract_address,
        'contractABI': contract_abi
    })

if __name__ == '__main__': 
    app.run(debug=True, port=5006)
