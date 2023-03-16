const crypto = require("crypto")

// importing the dependencies
const express = require("express")
const bodyParser = require("body-parser")
const cors = require("cors")
const helmet = require("helmet")
const morgan = require("morgan")

// defining the Express app
const app = express()

// adding Helmet to enhance your Rest API's security
app.use(helmet())

// using bodyParser to parse JSON bodies into JS objects
app.use(bodyParser.json())

// enabling CORS for all requests
app.use(cors())

// adding morgan to log HTTP requests
app.use(morgan("combined"))

const removeLinebreaks = (text) => {
	return text.replace(/\s+/g, "").trim()
}

const generateRSAKey = (keyLength) => {
	const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
		// The standard secure default length for RSA keys is 2048 bits
		modulusLength: keyLength,
	})

	const exportedPublicKeyBuffer = publicKey.export({
		type: "pkcs1",
		format: "pem",
	})

	const exportedPrivateKeyBuffer = privateKey.export({
		type: "pkcs1",
		format: "pem",
	})

	const publicKeyFinal = removeLinebreaks(exportedPublicKeyBuffer)
	const privateKeyFinal = removeLinebreaks(exportedPrivateKeyBuffer)

	const dataToSend = {
		public_key: publicKeyFinal,
		private_key: privateKeyFinal,
	}

	return dataToSend
}

// *********************************************************************
//
// To export the public key and write it to file:

// const exportedPublicKeyBuffer = publicKey.export({
// 	type: "pkcs1",
// 	format: "pem",
// })
// fs.writeFileSync("public.pem", exportedPublicKeyBuffer, { encoding: "utf-8" })
// *********************************************************************

// *********************************************************************
//
// To export the private key and write it to file

// const exportedPrivateKeyBuffer = privateKey.export({
// 	type: "pkcs1",
// 	format: "pem",
// })
// fs.writeFileSync("private.pem", exportedPrivateKeyBuffer, { encoding: "utf-8" })

// *********************************************************************

// defining an endpoint to return all ads
app.get("/", (req, res) => {
	const response = generateRSAKey(1024)
	res.send(response)
})

app.post("/generatekeypair", (req, res) => {
	if (!req.body.key) {
		res.send("The key parameter is required")
	}
	const keyLength = req.body.key
	const response = generateRSAKey(keyLength)
	res.header({ "Content-type": "application/json" })
	res.send(response)
})

// starting the server
app.listen(3001, () => {
	console.log("listening on port 3001")
})
