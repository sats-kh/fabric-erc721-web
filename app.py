from flask import Flask, render_template, request, redirect, url_for, jsonify, session
import sqlite3
import subprocess
import os
import json
import requests
import random

app = Flask(__name__)
app.secret_key = 'dev_secret_key'  # 연구용으로 간단한 비밀키 설정

# Stable Diffusion 서버 주소
SD_SERVER_URL = "http://210.125.67.57:5000/generate"

# SQLite 데이터베이스 초기화
DB_PATH = 'nft_service.db'

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS nfts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            token_id TEXT NOT NULL,
            token_uri TEXT NOT NULL,
            owner_id INTEGER NOT NULL,
            FOREIGN KEY (owner_id) REFERENCES users (id)
        )
    ''')
    conn.commit()
    conn.close()

init_db()

# 환경 변수 설정 (NFT Mint에 필요)
os.environ["CORE_PEER_TLS_ENABLED"] = "true"
os.environ["CORE_PEER_LOCALMSPID"] = "Org1MSP"
os.environ["CORE_PEER_MSPCONFIGPATH"] = "/home/kh/go/src/github.com/fabric-samples/test-network/organizations/peerOrganizations/org1.example.com/users/minter@org1.example.com/msp"
os.environ["CORE_PEER_TLS_ROOTCERT_FILE"] = "/home/kh/go/src/github.com/fabric-samples/test-network/organizations/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/ca.crt"
os.environ["CORE_PEER_ADDRESS"] = "localhost:7051"

TARGET_TLS_OPTIONS = [
    "-o", "localhost:7050",
    "--ordererTLSHostnameOverride", "orderer.example.com",
    "--tls",
    "--cafile", "/home/kh/go/src/github.com/fabric-samples/test-network/organizations/ordererOrganizations/example.com/orderers/orderer.example.com/msp/tlscacerts/tlsca.example.com-cert.pem",
    "--peerAddresses", "localhost:7051",
    "--tlsRootCertFiles", "/home/kh/go/src/github.com/fabric-samples/test-network/organizations/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/ca.crt",
    "--peerAddresses", "localhost:9051",
    "--tlsRootCertFiles", "/home/kh/go/src/github.com/fabric-samples/test-network/organizations/peerOrganizations/org2.example.com/peers/peer0.org2.example.com/tls/ca.crt"
]

# 홈 페이지
@app.route('/')
def home():
    user_logged_in = 'user_id' in session

    # Fabric 체인코드 호출로 모든 NFT 조회
    cmd = [
        "peer", "chaincode", "query",
        "-C", "mychannel",
        "-n", "token_erc721",
        "-c", '{"function":"QueryAllNFTs","Args":[]}'
    ]

    try:
        # Fabric 체인코드 호출
        result = subprocess.check_output(cmd, stderr=subprocess.STDOUT, text=True)
        print("Fabric query result:", result)  # 디버깅 로그
        nfts = json.loads(result)  # 체인코드에서 반환된 JSON 데이터를 파싱
    except subprocess.CalledProcessError as e:
        print(f"Chaincode query failed: {e.output}")
        return f"Chaincode query failed: {e.output}", 500
    except json.JSONDecodeError as e:
        print(f"JSON parsing error: {e}")
        return f"Failed to parse JSON response: {result}", 500

    # 데이터베이스에서 사용자 이름 조회
    all_nfts = []
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    for nft in nfts:
        token_id = nft.get("tokenId")
        token_uri = nft.get("tokenURI")

        # 데이터베이스에서 owner_id를 통해 사용자 이름 조회
        cursor.execute('''
            SELECT users.username
            FROM nfts
            INNER JOIN users ON nfts.owner_id = users.id
            WHERE nfts.token_id = ?
        ''', (token_id,))
        owner = cursor.fetchone()
        owner_username = owner[0] if owner else "Unknown"

        # 최종 NFT 데이터 구성
        all_nfts.append({
            "tokenId": token_id,
            "tokenURI": token_uri,
            "owner": owner_username
        })
    all_nfts = sorted(all_nfts, key=lambda x: int(x["tokenId"]), reverse=True)

    conn.close()

    return render_template('home.html', user_logged_in=user_logged_in, all_nfts=all_nfts)

# 회원가입 페이지
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()

        try:
            cursor.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, password))
            conn.commit()
        except sqlite3.IntegrityError:
            return "Username already exists", 400
        finally:
            conn.close()

        return redirect(url_for('home'))
    return render_template('register.html')



@app.route('/mint', methods=['GET', 'POST'])
def mint():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        # 사용자 입력 데이터
        try:
            prompt = request.form['prompt']
        except KeyError as e:
            return f"Missing form field: {e}", 400

        user_id = session['user_id']

        # 랜덤 Token ID 생성
        token_id = str(random.randint(1000, 9999))

        # Stable Diffusion 서버로 Prompt 전송
        try:
            sd_response = requests.post(SD_SERVER_URL, json={"prompt": prompt})
            sd_response.raise_for_status()
            sd_data = sd_response.json()
            token_uri = sd_data.get("ipfs_url")  # Stable Diffusion 서버에서 반환된 IPFS URL
            if not token_uri:
                return "Failed to retrieve IPFS URL from Stable Diffusion server.", 500
        except requests.RequestException as e:
            return f"Failed to communicate with Stable Diffusion server: {e}", 500

        # Fabric 네트워크에서 NFT Mint
        cmd = [
            "peer", "chaincode", "invoke",
            *TARGET_TLS_OPTIONS,
            "-C", "mychannel",
            "-n", "token_erc721",
            "-c", f'{{"function":"MintWithTokenURI","Args":["{token_id}", "{token_uri}"]}}'
        ]
        try:
            subprocess.check_output(cmd, stderr=subprocess.STDOUT, text=True)
        except subprocess.CalledProcessError as e:
            return f"Chaincode invocation failed: {e.output.strip()}", 500

        # 데이터베이스에 NFT 소유권 저장
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        try:
            cursor.execute(
                'INSERT INTO nfts (token_id, token_uri, owner_id) VALUES (?, ?, ?)',
                (token_id, token_uri, user_id)
            )
            conn.commit()
        except sqlite3.Error as e:
            return f"Failed to save NFT ownership to the database: {e}", 500
        finally:
            conn.close()

        # 성공 메시지 반환
        return render_template('mint_success.html', token_id=token_id, token_uri=token_uri, prompt=prompt)

    return render_template('mint.html')
# 로그인 페이지
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute('SELECT id FROM users WHERE username = ? AND password = ?', (username, password))
        user = cursor.fetchone()
        conn.close()

        if user:
            session['user_id'] = user[0]
            session['username'] = username  # 사용자 이름도 세션에 저장
            return redirect(url_for('home'))
        return "Invalid credentials", 401
    return render_template('login.html')

# 로그아웃
@app.route('/logout')
def logout():
    session.pop('user_id', None)
    session.pop('username', None)
    return redirect(url_for('home'))


# My NFTs 페이지
@app.route('/nfts', methods=['GET'])
def view_nfts():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']  # 현재 로그인한 사용자의 ID

    # 데이터베이스에서 현재 사용자가 소유한 NFT 정보 조회
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        SELECT nfts.token_id, nfts.token_uri, users.username
        FROM nfts
        INNER JOIN users ON nfts.owner_id = users.id
        WHERE nfts.owner_id = ?
        ORDER BY nfts.id DESC
    ''', (user_id,))
    user_nfts = cursor.fetchall()
    conn.close()

    # NFT 데이터를 리스트로 변환
    nfts = [
        {
            "tokenId": row[0],
            "tokenURI": row[1],
            "owner": row[2]
        } for row in user_nfts
    ]

    return render_template('nfts.html', nfts=nfts)

if __name__ == '__main__':
    app.run(host="0.0.0.0", port=3000, debug=True)

