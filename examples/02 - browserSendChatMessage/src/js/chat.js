const jsSha256 = require('js-sha256'),
    google_protobuf_timestamp_pb = require('google-protobuf/google/protobuf/timestamp_pb.js'),
    multihash = require('multihashes'),
    myProtos = require("../../protobufs/message_pb"),
    // utility = require("./utility"),
    google_protobuf_any_pb = require('google-protobuf/google/protobuf/any_pb.js'),
    nacl = require("tweetnacl"),
    naclUtil = require("tweetnacl-util"),
    { hmac, keys } = require('libp2p-crypto'),
    ed2curve = require("ed2curve");

const cryptoUtility = require("./cryptoUtility"),
    request = require("./request"),
    dom = require("./dom"),
    socket = require("./socket");

// Temporarily used to generate seed
sessionStorage.setItem('sessionLogin', 'surround style hotel scale noble portion erupt early ancient color noise unaware')

const generateEncryptedCiphertext = async (recipientPublicKeyB64, chatMessage, dateNow, seed, subject = "") => {

    // The chat message contains a timestamp. This must be in the protobuf 'Timestamp' format.
    const timestamp = new google_protobuf_timestamp_pb.Timestamp();

    timestamp.fromDate(dateNow);

    // The messageID is derived from the message data. In this cse its the hash of the message,
    // subject and timestamp which is then multihash encoded.
    // const combinationString = chatMessage + subject + dateNow.toISOString();
    // const combinationString = `${chatMessage}2018-10-09T06:30:00Z`;
    const combinationString = `${chatMessage}${subject}${dateNow.toISOString()}`,

    idBytes = jsSha256.array(combinationString),
    idBytesArray = new Uint8Array(idBytes),
    idBytesBuffer = new Buffer(idBytesArray.buffer),
    encoded = multihash.encode(idBytesBuffer, 0x12);

    // Create the Chat PB
    const chatPb = new myProtos.Chat(),
    b58MsgID = multihash.toB58String(encoded);


    chatPb.setMessageid(multihash.toB58String(encoded));
    chatPb.setSubject(subject);
    chatPb.setMessage(chatMessage);
    chatPb.setTimestamp(timestamp);
    chatPb.setFlag(myProtos.Chat.Flag.MESSAGE);
    // console.debug(chatPb.toObject());

    const payload = chatPb.serializeBinary(),

    // Now we wrap it in a pb.Message object.

    any = new google_protobuf_any_pb.Any();
    any.setTypeUrl('type.googleapis.com/Chat');
    any.setValue(payload);

    const message = new myProtos.Message();
    message.setMessagetype(myProtos.Message.MessageType.CHAT);
    message.setPayload(any);

    // Use the protobuf serialize function to convert the object to a serialized byte array
    const serializedMessage = message.serializeBinary(),

    edd2519PrivateKey = await cryptoUtility.identityKeyFromSeed(seed),

    signature = await cryptoUtility.signIt(edd2519PrivateKey, serializedMessage);

    // Create the envelope
    const envelope = new myProtos.Envelope();
    envelope.setMessage(message);
    envelope.setPubkey(edd2519PrivateKey.public.bytes);
    envelope.setSignature(signature);

    // ----- STEP 2: Encrypt the serialized envelope using the recipient's public key. For this you
    // will need to use an nacl library. NOTE for this you will need the recipient's public key.
    // We will have to create a server endpoint to get the pubkey. Technically I think the gateway
    // already has one but we may need to improve it for this purpose. The public key is also found
    // inside a listing so if you're looking at a listing you should already have it.

    // Serialize the envelope
    const serializedEnvelope = envelope.serializeBinary(),

    // Recipient public key
    recipientPublicKey = naclUtil.decodeBase64(recipientPublicKeyB64),

    // Generate ephemeral key pair
    ephemeralKeyPair = nacl.box.keyPair(),
    pub = keys.unmarshalPublicKey(recipientPublicKey),

    cPubkey = ed2curve.convertPublicKey(pub._key),

    // Encrypt with NACL
    nonce = nacl.randomBytes(24),

    cipherText = nacl.box(serializedEnvelope, nonce, cPubkey, ephemeralKeyPair.secretKey),

    // Prepend the ephemeral public key to the ciphertext
    // Prepend nonce to the ephemPubkey+ciphertext
    combined = [...nonce, ...ephemeralKeyPair.publicKey, ...cipherText],

    // Base64Encode
    encodedCipherText = naclUtil.encodeBase64(combined);
    return encodedCipherText;
}



exports.sendChatMessage = async () => {
    dom.triggerSendMessageLoader();

    const recipientPeerID = document.getElementById("recipientPeerID").value,
        chatMessage = document.getElementById("chatMessage").value,
        mnemonicSeed = document.getElementById("userMnemonicSeed").value,
        date = new Date(),
        messageID = cryptoUtility.uuidv4(),
        recipientPublicKeyB64 = await request.getRecipientPublicKeyB64(recipientPeerID);
    if (recipientPublicKeyB64) {
        try {
            const encryptedMessage = await generateEncryptedCiphertext(recipientPublicKeyB64, chatMessage, date, mnemonicSeed);

            formattedMessage = {
                    encryptedMessage: encryptedMessage,
                    recipient: recipientPeerID
                },

                // Generate the authentication message and send it to the relay.
                typedMessage = {
                    Type: "EncryptedMessage",
                    Data: formattedMessage
                }

            socket.forwardMessageToWebRelay(JSON.stringify(typedMessage));
            dom.sendMessageResponse(`Success: Sent!`, "success");
        } catch (e) {
            console.error(e)
        }
    }

}