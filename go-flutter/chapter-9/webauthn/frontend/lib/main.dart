import 'package:flutter/material.dart';
import 'package:http/http.dart' as http;
import 'package:web/web.dart' as web;
import 'package:uuid/uuid.dart';
import 'dart:convert';
import 'dart:typed_data';
import 'dart:js_interop';

void main() {
  runApp(const WebAuthnApp());
}

class WebAuthnApp extends StatelessWidget {
  const WebAuthnApp({super.key});

  // This widget is the root of your application.
  @override
  Widget build(BuildContext context) {
    return const MaterialApp(
      title: 'WebAuthn Demo',
      home: WebauthnPage(title: 'WebAuthn Demo Page'),
    );
  }
}

const padding = Padding(padding: EdgeInsets.all(10));

class WebauthnPage extends StatelessWidget {
  const WebauthnPage({super.key, required this.title});

  final String title;

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: Text(title),
      ),
      body: Table(
        children: const [
          TableRow(
            children: <Widget>[
              padding,
              RegistrationView(),
              padding,
              AuthenticationView(),
              padding,
            ],
          ),
        ],
      ),
    );
  }
}

class RegistrationView extends StatefulWidget {
  const RegistrationView({super.key});

  @override
  State<RegistrationView> createState() => _RegistrationViewState();
}

Future<Map> httpPost(String path, Map<String, dynamic> params, Object? body) {
  var js = "";

  if (body != null) {
    js = jsonEncode(body);
  }
  return http
      .post(
    Uri(scheme: "https", path: path, queryParameters: params),
    headers: {"Content-Type": "application/json"},
    body: js,
  )
      .then((res) {
    if (res.statusCode == 200) {
      return jsonDecode(res.body);
    } else {
      throw Exception("${res.statusCode} ${res.body}");
    }
  });
}

ByteBuffer str2buffer(String s) {
  final normalized = s
      .replaceAll('-', '+')
      .replaceAll('_', '/')
      .padRight((s.length + 3) ~/ 4 * 4, '=');

  return base64Url.decode(normalized).buffer;
}

String buffer2str(ByteBuffer buf) {
  return base64UrlEncode(buf.asUint8List());
}

class _RegistrationViewState extends State<RegistrationView> {
  final TextEditingController userCtrl = TextEditingController();
  String regStatus = "";
  @override
  Widget build(BuildContext context) {
    return Column(
      children: <Widget>[
        const Text("Registration View"),
        padding,
        TextField(
          decoration: const InputDecoration(
            border: UnderlineInputBorder(),
            hintText: 'Username',
          ),
          controller: userCtrl,
        ),
        padding,
        ValueListenableBuilder(
          valueListenable: userCtrl,
          builder: (context, uctrl, child) {
            return ElevatedButton(
              onPressed: uctrl.text.isEmpty
                  ? null
                  : () async {
                      try {
                        final state = const Uuid().v4();
                        final res = await httpPost(
                            "/webauthn/register/begin",
                            {
                              "username": userCtrl.text,
                              "state": state,
                            },
                            null);

                        Map<String, dynamic> publicKey = res["publicKey"];
                        final challenge = publicKey["challenge"];
                        publicKey["challenge"] = str2buffer(challenge).toJS;
                        var user = publicKey["user"];
                        user["id"] = str2buffer(user["id"]).toJS;
                        publicKey["user"] = user;

                        final publicKeyOpts = publicKey.jsify()
                            as web.PublicKeyCredentialCreationOptions;
                        final options = web.CredentialCreationOptions(
                            publicKey: publicKeyOpts);
                        final cred = await web.window.navigator.credentials
                            .create(options)
                            .toDart;

                        if (cred == null) {
                          throw Exception("Failed to acquire credentials.");
                        } else {
                          final pubKeyCred = cred as web.PublicKeyCredential;
                          final response = pubKeyCred.response
                              as web.AuthenticatorAttestationResponse;

                          final obj = {
                            "id": pubKeyCred.id,
                            "rawId": buffer2str(pubKeyCred.rawId.toDart),
                            "type": 'public-key',
                            "response": {
                              "attestationObject":
                                  buffer2str(response.attestationObject.toDart),
                              "clientDataJson": buffer2str(
                                  pubKeyCred.response.clientDataJSON.toDart),
                            },
                          };

                          final res1 = await httpPost(
                              "/webauthn/register/finish",
                              {
                                "username": userCtrl.text,
                                "state": state,
                              },
                              obj);
                          setState(() {
                            regStatus = res1["message"];
                          });
                        }
                      } catch (e) {
                        setState(() {
                          regStatus = e.toString();
                        });
                      }
                    },
              child: const Text("Register"),
            );
          },
        ),
        Text(regStatus),
      ],
    );
  }
}

class AuthenticationView extends StatefulWidget {
  const AuthenticationView({super.key});

  @override
  State<AuthenticationView> createState() => _AuthenticationViewState();
}

class _AuthenticationViewState extends State<AuthenticationView> {
  final TextEditingController userCtrl = TextEditingController();
  String authStatus = "";
  @override
  Widget build(BuildContext context) {
    return Column(
      children: [
        const Text("Authentication View"),
        padding,
        TextField(
          decoration: const InputDecoration(
            border: UnderlineInputBorder(),
            hintText: 'Username',
          ),
          controller: userCtrl,
        ),
        padding,
        ValueListenableBuilder(
          valueListenable: userCtrl,
          builder: (context, uctrl, child) {
            return ElevatedButton(
              onPressed: uctrl.text.isEmpty
                  ? null
                  : () async {
                      try {
                        final state = const Uuid().v4();
                        final res = await httpPost(
                            "/webauthn/login/begin",
                            {
                              "username": userCtrl.text,
                              "state": state,
                            },
                            null);

                        Map<String, dynamic> publicKey = res["publicKey"];
                        final challenge = publicKey["challenge"];
                        publicKey["challenge"] = str2buffer(challenge).toJS;

                        var allowedcreds = publicKey["allowCredentials"];

                        for (int i = 0; i < allowedcreds.length; i++) {
                          final cid = allowedcreds[i]["id"];
                          allowedcreds[i]["id"] = str2buffer(cid).toJS;
                        }
                        publicKey["allowCredentials"] = allowedcreds;

                        final publicKeyOpts = publicKey.jsify()
                            as web.PublicKeyCredentialRequestOptions;

                        final options = web.CredentialRequestOptions(
                          publicKey: publicKeyOpts,
                        );

                        final cred = await web.window.navigator.credentials
                            .get(options)
                            .toDart;

                        if (cred == null) {
                          throw Exception("Failed to acquire credentials.");
                        } else {
                          final pubKeyCred = cred as web.PublicKeyCredential;
                          final response = pubKeyCred.response
                              as web.AuthenticatorAssertionResponse;

                          final obj = {
                            "id": cred.id,
                            "rawId": buffer2str(pubKeyCred.rawId.toDart),
                            "type": 'public-key',
                            "response": {
                              "authenticatorData":
                                  buffer2str(response.authenticatorData.toDart),
                              "signature":
                                  buffer2str(response.signature.toDart),
                              "clientDataJson":
                                  buffer2str(response.clientDataJSON.toDart),
                            },
                          };

                          final res1 = await httpPost(
                              "/webauthn/login/finish",
                              {
                                "username": userCtrl.text,
                                "state": state,
                              },
                              obj);
                          setState(() {
                            authStatus = res1["message"];
                          });
                        }
                      } catch (e) {
                        setState(() {
                          authStatus = e.toString();
                        });
                      }
                    },
              child: const Text("Authenticate"),
            );
          },
        ),
        Text(authStatus),
      ],
    );
  }
}
