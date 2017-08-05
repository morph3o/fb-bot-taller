/*
 * Copyright 2016-present, Facebook, Inc.
 * All rights reserved.
 *
 * This source code is licensed under the license found in the
 * LICENSE file in the root directory of this source tree.
 *
 */

/* jshint node: true, devel: true */
'use strict';

const 
  bodyParser = require('body-parser'),
  config = require('config'),
  crypto = require('crypto'),
  express = require('express'),
  https = require('https'),  
  request = require('request'),
  logger = require('winston');

var app = express();
app.set('port', process.env.PORT || 5000);
app.set('view engine', 'ejs');
app.use(bodyParser.json({ verify: verifyRequestSignature }));
app.use(express.static('public'));


const TIPOS_PANES = 'TIPOS_PANES';


/**
 * Verificando que los datos de configuracion no están vacíos
 * */
const APP_SECRET = (process.env.MESSENGER_APP_SECRET) ? 
  process.env.MESSENGER_APP_SECRET :
  config.get('appSecret');

const VALIDATION_TOKEN = (process.env.MESSENGER_VALIDATION_TOKEN) ?
  (process.env.MESSENGER_VALIDATION_TOKEN) :
  config.get('validationToken');

const PAGE_ACCESS_TOKEN = (process.env.MESSENGER_PAGE_ACCESS_TOKEN) ?
  (process.env.MESSENGER_PAGE_ACCESS_TOKEN) :
  config.get('pageAccessToken');

const SERVER_URL = (process.env.SERVER_URL) ?
  (process.env.SERVER_URL) :
  config.get('serverURL');

if (!(APP_SECRET && VALIDATION_TOKEN && PAGE_ACCESS_TOKEN && SERVER_URL)) {
  logger.error('Missing config values');
  process.exit(1);
}

/**
 * Endpoint necesario para poder hacer la validación con facebook
 * */
app.get('/webhook', function(req, res) {
  if (req.query['hub.mode'] === 'subscribe' &&
      req.query['hub.verify_token'] === VALIDATION_TOKEN) {
    logger.info('Validating webhook');
    res.status(200).send(req.query['hub.challenge']);
  } else {
    logger.error('Failed validation. Make sure the validation tokens match.');
    res.sendStatus(403);          
  }  
});


/**
 * Este endpoint se preocupa de manejar los mensajes que se envian al chat. Todos los mensajes
 * son de tipo POST.
 * */
app.post('/webhook', function (req, res) {
  var data = req.body;

  // Make sure this is a page subscription
  if (data.object == 'page') {
    // Iterate over each entry
    // There may be multiple if batched
    data.entry.forEach(function(pageEntry) {
      var pageID = pageEntry.id;
      var timeOfEvent = pageEntry.time;

      pageEntry.messaging.forEach(function(messagingEvent) {
        if (messagingEvent.optin) {
          receivedAuthentication(messagingEvent);
        } else if (messagingEvent.message) {
          receivedMessage(messagingEvent);
        } else if (messagingEvent.delivery) {
          receivedDeliveryConfirmation(messagingEvent);
        } else if (messagingEvent.postback) {
          receivedPostback(messagingEvent);
        } else if (messagingEvent.read) {
          receivedMessageRead(messagingEvent);
        } else if (messagingEvent.account_linking) {
          receivedAccountLink(messagingEvent);
        } else {
          logger.info('Webhook received unknown messagingEvent: ', messagingEvent);
        }
      });
    });

    res.sendStatus(200);
  }
});

/*
 * This path is used for account linking. The account linking call-to-action
 * (sendAccountLinking) is pointed to this URL. 
 * 
 */
app.get('/authorize', function(req, res) {
  var accountLinkingToken = req.query.account_linking_token;
  var redirectURI = req.query.redirect_uri;

  // Authorization Code should be generated per user by the developer. This will 
  // be passed to the Account Linking callback.
  var authCode = '1234567890';

  // Redirect users to this URI on successful login
  var redirectURISuccess = redirectURI + '&authorization_code=' + authCode;

  res.render('authorize', {
    accountLinkingToken: accountLinkingToken,
    redirectURI: redirectURI,
    redirectURISuccess: redirectURISuccess
  });
});

/**
 * Método que verifica que el mensaje viene desde facebook.
 *
 * https://developers.facebook.com/docs/graph-api/webhooks#setup
 *
 */
function verifyRequestSignature(req, res, buf) {
  var signature = req.headers['x-hub-signature'];

  if (!signature) {
    // For testing, let's log an error. In production, you should throw an 
    // error.
    logger.error('Couldn\'t validate the signature.');
  } else {
    var elements = signature.split('=');
    var method = elements[0];
    var signatureHash = elements[1];

    var expectedHash = crypto.createHmac('sha1', APP_SECRET)
                        .update(buf)
                        .digest('hex');

    if (signatureHash != expectedHash) {
      throw new Error('Couldn\'t validate the request signature.');
    }
  }
}

/*
 * Authorization Event
 *
 * The value for 'optin.ref' is defined in the entry point. For the "Send to 
 * Messenger" plugin, it is the 'data-ref' field. Read more at 
 * https://developers.facebook.com/docs/messenger-platform/webhook-reference/authentication
 *
 */
function receivedAuthentication(event) {
  var senderID = event.sender.id;
  var recipientID = event.recipient.id;
  var timeOfAuth = event.timestamp;

  // The 'ref' field is set in the 'Send to Messenger' plugin, in the 'data-ref'
  // The developer can set this to an arbitrary value to associate the 
  // authentication callback with the 'Send to Messenger' click event. This is
  // a way to do account linking when the user clicks the 'Send to Messenger' 
  // plugin.
  var passThroughParam = event.optin.ref;

  logger.info('Received authentication for user %d and page %d with pass ' +
    'through param "%s" at %d', senderID, recipientID, passThroughParam,
    timeOfAuth);

  // When an authentication is received, we'll send a message back to the sender
  // to let them know it was successful.
  sendTextMessage(senderID, 'Authentication successful');
}

/**
 * Message Event
 *
 * Este evento sucede cuando un mensaje es enviado a tu pagina mediante el chat. El objeto
 * 'mensaje' puede variar dependiendo del tipo de mensaje recibido. Mas detalles a continuación:
 *
 * https://developers.facebook.com/docs/messenger-platform/webhook-reference/message-received
 * 
 */
function receivedMessage(event) {
  var senderID = event.sender.id;
  var recipientID = event.recipient.id;
  var timeOfMessage = event.timestamp;
  var message = event.message;

  logger.info('Received message for user %d and page %d at %d with message:',
    senderID, recipientID, timeOfMessage);
  logger.info(JSON.stringify(message));

  var isEcho = message.is_echo;
  var messageId = message.mid;
  var appId = message.app_id;
  var metadata = message.metadata;

  // You may get a text or attachment but not both
  var messageText = message.text;
  var messageAttachments = message.attachments;
  var quickReply = message.quick_reply;

  if (isEcho) {
    // Just logging message echoes to console
    logger.info('Received echo for message %s and app %d with metadata %s',
      messageId, appId, metadata);
    return;
  } else if (quickReply) {
    var quickReplyPayload = quickReply.payload;
    logger.info('Quick reply for message %s with payload %s',
      messageId, quickReplyPayload);

    sendTextMessage(senderID, 'Quick reply tapped');
    return;
  }

  if (messageText) {
    switch (messageText) {
      case TIPOS_PANES:
        sendTiposDePanes(senderID);
        break;
      default:
        var welcomeMessage = 'Hola! Bienvenido a Pancitos DevC. En que te podemos ayudar?';
        sendTextMessage(senderID, welcomeMessage);
    }
  } else if (messageAttachments) {
    sendTextMessage(senderID, 'Message with attachment received');
  }
}

function sendTiposDePanes(recipientId) {
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      attachment: {
        type: "template",
        payload: {
          template_type: "generic",
          elements: [{
            title: "Pan Pita",
            subtitle: "El más exquisito pan pita del mundo",
            item_url: "http://www.pancitosdevc.cl/panpita",
            image_url: "https://s-media-cache-ak0.pinimg.com/originals/55/4f/fb/554ffb0678dca55167e0d74ee0806a4f.jpg",
            buttons: [{
              type: "web_url",
              url: "http://www.pancitosdevc.cl/panpita",
              title: "Open Web URL"
            }, {
              type: "postback",
              title: "Call Postback",
              payload: "Payload for first bubble",
            }],
          }, {
            title: "Pan Batido",
            subtitle: "El más exquisito pan batido del mundo",
            item_url: "http://www.pancitosdevc.cl/panpita",
            image_url: "https://imageneselsalvador.files.wordpress.com/2015/04/pan-batido.jpg",
            buttons: [{
              type: "web_url",
              url: "http://www.pancitosdevc.cl/panpita",
              title: "Open Web URL"
            }, {
              type: "postback",
              title: "Call Postback",
              payload: "Payload for first bubble",
            }],
          }, {
            title: "Dobladitas",
            subtitle: "La más exquisita dobladita del mundo",
            item_url: "http://www.pancitosdevc.cl/panpita",
            image_url: "https://gcdn.emol.cl/cocina/files/2015/09/Dobladitas.jpg",
            buttons: [{
              type: "web_url",
              url: "http://www.pancitosdevc.cl/panpita",
              title: "Open Web URL"
            }, {
              type: "postback",
              title: "Call Postback",
              payload: "Payload for first bubble",
            }],
          }]
        }
      }
    }
  };

  callSendAPI(messageData);
}

/*
 * Send a text message using the Send API.
 *
 */
function sendTextMessage(recipientId, messageText) {
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      attachment: {
        type: "template",
        payload: {
          template_type: "button",
          text: messageText,
          buttons:[{
            type: "web_url",
            url: "https://www.facebook.com/pancitosdevc/",
            title: "Nuestra pagina Web"
          }, {
            type: "postback",
            title: "Tipos de Panes",
            payload: TIPOS_PANES
          }, {
            type: "phone_number",
            title: "Llámanos",
            payload: "+16505551234"
          }]
        }
      }
    }
  };

  callSendAPI(messageData);
}

/*
 * Call the Send API. The message data goes in the body. If successful, we'll 
 * get the message id in a response 
 *
 */
function callSendAPI(messageData) {
  request({
    uri: 'https://graph.facebook.com/v2.8/me/messages',
    qs: { access_token: PAGE_ACCESS_TOKEN },
    method: 'POST',
    json: messageData
  }, function (error, response, body) {
    if (!error && response.statusCode == 200) {
      var recipientId = body.recipient_id;
      var messageId = body.message_id;

      if (messageId) {
        logger.info('Successfully sent message with id %s to recipient %s',
          messageId, recipientId);
      } else {
      logger.info('Successfully called Send API for recipient %s',
        recipientId);
      }
    } else {
      logger.error('Failed calling Send API', response.statusCode, response.statusMessage, body.error);
    }
  });  
}

/*
 * Delivery Confirmation Event
 *
 * This event is sent to confirm the delivery of a message. Read more about
 * these fields at https://developers.facebook.com/docs/messenger-platform/webhook-reference/message-delivered
 *
 */
function receivedDeliveryConfirmation(event) {
    var senderID = event.sender.id;
    var recipientID = event.recipient.id;
    var delivery = event.delivery;
    var messageIDs = delivery.mids;
    var watermark = delivery.watermark;
    var sequenceNumber = delivery.seq;

    if (messageIDs) {
        messageIDs.forEach(function(messageID) {
            logger.info('Received delivery confirmation for message ID: %s',
                messageID);
        });
    }

    logger.info('All message before %d were delivered.', watermark);
}


/*
 * Postback Event
 *
 * This event is called when a postback is tapped on a Structured Message.
 * https://developers.facebook.com/docs/messenger-platform/webhook-reference/postback-received
 *
 */
function receivedPostback(event) {
    var senderID = event.sender.id;
    var recipientID = event.recipient.id;
    var timeOfPostback = event.timestamp;

    // The 'payload' param is a developer-defined field which is set in a postback
    // button for Structured Messages.
    var payload = event.postback.payload;

    logger.info('Received postback for user %d and page %d with payload "%s" ' +
        'at %d', senderID, recipientID, payload, timeOfPostback);

    switch (payload) {
      case TIPOS_PANES:
        sendTiposDePanes(senderID);
        break;
    }
}

/*
 * Message Read Event
 *
 * This event is called when a previously-sent message has been read.
 * https://developers.facebook.com/docs/messenger-platform/webhook-reference/message-read
 *
 */
function receivedMessageRead(event) {
    var senderID = event.sender.id;
    var recipientID = event.recipient.id;

    // All messages before watermark (a timestamp) or sequence have been seen.
    var watermark = event.read.watermark;
    var sequenceNumber = event.read.seq;

    logger.info('Received message read event for watermark %d and sequence ' +
        'number %d', watermark, sequenceNumber);
}

/*
 * Account Link Event
 *
 * This event is called when the Link Account or UnLink Account action has been
 * tapped.
 * https://developers.facebook.com/docs/messenger-platform/webhook-reference/account-linking
 *
 */
function receivedAccountLink(event) {
    var senderID = event.sender.id;
    var recipientID = event.recipient.id;

    var status = event.account_linking.status;
    var authCode = event.account_linking.authorization_code;

    logger.info('Received account link event with for user %d with status %s ' +
        'and auth code %s ', senderID, status, authCode);
}

// Start server
// Webhooks must be available via SSL with a certificate signed by a valid 
// certificate authority.
app.listen(app.get('port'), function() {
  logger.info('Node app is running on port', app.get('port'));
});

module.exports = app;

