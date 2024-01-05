from collections.abc import Mapping
from web3 import Web3
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import json

class BlockchainNode:

            def __init__(self, w3, address):
                self.address = address
                self.w3 = w3
                self.balance = w3.eth.get_balance(address)

            def send_transaction(self, transaction, private_key , signature):
                value = transaction.get("value")  # Récupération de la valeur de la transaction
                if value > self.balance:
                    print(f"İşlem imkansız: Yetersiz bakiye ({self.balance} ETH)")
                    return None

                signed_transaction = self.w3.eth.account.sign_transaction(transaction, private_key)

                transaction_hash = self.w3.eth.send_raw_transaction(signed_transaction.rawTransaction)

                if transaction_hash is not None:
                    self.balance -= value  # Mise à jour du solde localement
                    print(f"İşlem başarıyla gönderildi. Yeni denge: {self.balance} ETH")
                    return transaction_hash, get_random_bytes(16)
                client_list = [self.node1, self.node2]  # Liste des clients
                encryption_key =  get_random_bytes(16)       
                encrypted_transaction = self.encrypt(transaction, encryption_key)  # Cryptez la transaction
                for other_client in client_list:
                    if other_client != self:
                        other_client.receive_transaction(encrypted_transaction, encryption_key)

                return transaction_hash 
            def receive_transaction(self, transaction, encryption_key):
                if isinstance(transaction, dict):  # Vérifiez si la transaction est cryptée
                    decrypted_transaction = self.decrypt(transaction, encryption_key)
                    transaction = decrypted_transaction

                if isinstance(transaction, bytes):  # Vérifiez si la transaction est cryptée
                    decrypted_transaction_bytes = self.decrypt(transaction, encryption_key)
                    transaction = json.loads(decrypted_transaction_bytes)
                value = transaction.get("value")  # Récupération de la valeur de la transaction
                if value is not None:
                    # Mise à jour du solde du compte
                    self.balance += value
                    print(f"Musteri {self.address} alınan işlem: {transaction}")
                    print(f"Yeni bakiiye: {self.balance} ETH")


            def create_transaction(self, recipient, data, password1 , password2):
                data_hex = self.w3.to_hex(text=str(data))

                correct_nonce = self.w3.eth.get_transaction_count(self.w3.eth.accounts[2])

                nonce = self.w3.eth.get_transaction_count(self.address)

                # Définir le prix du gaz et la limite de gaz (ces valeurs peuvent être ajustées en fonction de votre réseau)
                gas_price = self.w3.eth.gas_price
                gas_limit = 6721975

                signature = self.generate_signature(password1, password2 , nonce, gas_price, gas_limit)


                transaction = {
                    "from": self.address,
                    "to": recipient,
                    "data": data_hex,
                    "value": 999888252799999999,
                    "nonce": 0,
                    "gasPrice": gas_price,
                    "gas": gas_limit,
                    "nonce" : correct_nonce,
                    "chainId" :1337,
                }

                transaction["nonce"] = nonce

                private_key = "0x4e00fa33f7af8782b8ac661a72d6336868434455ba1a9b2ac926f7541e3620d3"
                signed_transaction = self.w3.eth.account.sign_transaction(transaction, private_key)
                transaction_hash = self.w3.eth.send_raw_transaction(signed_transaction.rawTransaction)

                
                return transaction , signature , transaction_hash
            

            def generate_signature(self, password1, password2,nonce, gas_price, gas_limit):
                # Vous devez implémenter la logique de hachage ou d'une autre méthode de signature ici
                # Exemple: Utilisation de hashlib pour hacher les mots de passe
                import hashlib
                combined_password = password1 + password2 + str(nonce) + str(gas_price) + str(gas_limit)
                signature = hashlib.sha256(combined_password.encode()).hexdigest()
                return signature
            

            def receive_packets(self, packets):
                for packet in packets:
                    print(f"Node {self.address} received packet: {packet}")

            def send_packets(self, packets):
                for packet in packets:
                    print(f"Node {self.address} sending packet to client: {packet['recipient']}")
                    # Le nœud intermédiaire peut envoyer des paquets directement aux clients ou à d'autres nœuds intermédiaires
                    self.send_packet(packet, packet["recipient"])

            def send_packet(self, packet, recipient_address):
                print(f"Node {self.address} sending packet to {recipient_address}: {packet}")

            def encrypt(self, data, key):
                cipher = AES.new(key, AES.MODE_EAX)
                data_str = json.dumps(data)  # Convertissez le dictionnaire en chaîne JSON
                ciphertext, tag = cipher.encrypt_and_digest(data_str.encode('utf-8'))
                return cipher.nonce + tag + ciphertext

            def decrypt(self, encrypted_data, key):
                if isinstance(encrypted_data, bytes):
                    nonce, tag, ciphertext = encrypted_data.split(b"\x00")
                else: 
                    return encrypted_data               
                cipher = AES.new(key, AES.MODE_EAX, nonce)
                try:
                    decrypted_data = cipher.decrypt_and_verify(ciphertext, tag).decode('utf-8')
                    return decrypted_data
                except ValueError:
                    print(f"Error decrypting data: Authentication failed")
                    return None


class Blockchain:

    def __init__(self, http_provider):
        self.w3 = Web3(Web3.HTTPProvider(http_provider))
    
    def get_node(self, address):
        return BlockchainNode(self.w3, address)
    

class MainApp:

    def __init__(self):

        self.blockchain = Blockchain("http://127.0.0.1:8551")
        self.node1 = self.blockchain.get_node("0x81Bad2496420271Bf42309E024E07A0869A36BF0")
        self.node2 = self.blockchain.get_node("0x30d473E6D9a596E2C8A0aB0Bb2a2ACC71D31BE91")
        # Passwords for transactions
        self.password1 = "zoo prevent awake unhappy chest cradle correct immense fit acoustic merge frequent"
        self.password2 = "flash stick layer where bless crane office strong fragile other acid wine"
        self.password3 = "above carbon benefit clump spatial thank city bubble canyon interest abandon question"


    def run(self):
        # Client 1 envoie une transaction à Client 2
        private_key_node1 = "0x4e00fa33f7af8782b8ac661a72d6336868434455ba1a9b2ac926f7541e3620d3"
        transaction, signature , transaction_hash= self.node1.create_transaction(self.node2.address, 10, self.password1, self.password2)
        # = self.node1.send_transaction(transaction, private_key_node1 , signature)
        encryption_key= self.node1.send_transaction(transaction , private_key_node1 ,signature)

        self.node2.receive_transaction(transaction, encryption_key)

        print(f"Transaction hash1: {encryption_key}")

        packet_to_node1 = {"recipient": self.node2.address, 10: "EncryptedData1"}

        self.node1.receive_packets([packet_to_node1])

if __name__ == "__main__":
    main_app = MainApp()
    main_app.run()

