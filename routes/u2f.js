'use strict'

var insecurity = require('../lib/insecurity')
var u2f = require('u2f')

exports.registerRequest = function () {
  return function (req, res) {
    var user = insecurity.authenticatedUsers.from(req)
    var authRequest = u2f.request(req.headers.host)
    user.authRequest = authRequest
    res.send(JSON.stringify(authRequest))
  }
}

exports.register = function () {
  return function (req, res) {
    var user = insecurity.authenticatedUsers.from(req)
    var checkRes = u2f.checkRegistration(
      user.authRequest,
      req.body
    )
    if (checkRes.successful) {
      user.publicKey = checkRes.publicKey
      user.keyHandle = checkRes.keyHandle
      res.send(true)
    } else {
      res.send(checkRes.errorMessage)
    }
  }
}

exports.signRequest = function () {
  return function (req, res) {
    var user = insecurity.authenticatedUsers.from(req)
    var authRequest = u2f.request(req.headers.host, user.authRequest.keyHandle)
    user.authRequest = authRequest
    res.send(JSON.stringify(authRequest))
  }
}

exports.sign = function () {
  return function (req, res) {
    var user = insecurity.authenticatedUsers.from(req)
    var checkRes = u2f.checkSignature(
      user.authRequest,
      req.body,
      user.publicKey
    )
    if (checkRes.successful) {
      res.send({ success: true })
    } else {
      res.send({ error: checkRes.errorMessage })
    }
  }
}
