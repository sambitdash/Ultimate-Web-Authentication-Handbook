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

class WebAuthnState extends ValueNotifier<int> {
  WebAuthnState() : super(0);
  web.AbortController? _controller;

  web.AbortSignal renewSignal() {
    _controller?.abort();
    _controller = web.AbortController();
    return _controller!.signal;
  }

  void cancelAll() {
    _controller?.abort();
    _controller = null;
  }

  void notifyRestart() {
    value++;
  }
}

final _webauthnState = WebAuthnState();
const padding = Padding(padding: EdgeInsets.all(10));
final _uuid = const Uuid();

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

class WebauthnPage extends StatelessWidget {
  const WebauthnPage({super.key, required this.title});

  final String title;

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        centerTitle: true,
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
              DiscoverPasskeyAuthenticationView(),
              padding,
            ],
          ),
        ],
      ),
    );
  }
}

Future<Map> httpPost(
    String path, Map<String, dynamic> params, Object? body) async {
  var js = "";

  if (body != null) {
    js = jsonEncode(body);
  }
  final res = await http.post(
      Uri(scheme: "https", path: path, queryParameters: params),
      headers: {"Content-Type": "application/json"},
      body: js);
  if (res.statusCode == 200) {
    return jsonDecode(res.body);
  }
  throw Exception("code:${res.statusCode} message:${res.body}");
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

Future<(String, web.PublicKeyCredential?)> createCredential(
    String username) async {
  final state = _uuid.v4();
  var params = {"state": state, "username": username};
  final res = await httpPost("/webauthn/register/begin", params, null);

  debugPrint(res.toString());

  Map<String, dynamic> publicKey = res as Map<String, dynamic>;
  final challenge = publicKey["challenge"];
  publicKey["challenge"] = str2buffer(challenge).toJS;
  var user = publicKey["user"];
  user["id"] = str2buffer(user["id"]).toJS;
  publicKey["user"] = user;

  final publicKeyOpts =
      publicKey.jsify() as web.PublicKeyCredentialCreationOptions;
  debugPrint(publicKeyOpts.toString());
  final signal = _webauthnState.renewSignal();
  final options =
      web.CredentialCreationOptions(publicKey: publicKeyOpts, signal: signal);
  final cred = await web.window.navigator.credentials.create(options).toDart;
  debugPrint(cred.toString());
  return (state, cred as web.PublicKeyCredential?);
}

Future<String> postAttestationResponse(
    web.PublicKeyCredential credential, String state, String username) async {
  final response = credential.response as web.AuthenticatorAttestationResponse;

  final obj = {
    "id": credential.id,
    "rawId": buffer2str(credential.rawId.toDart),
    "type": 'public-key',
    "response": {
      "attestationObject": buffer2str(response.attestationObject.toDart),
      "clientDataJson": buffer2str(response.clientDataJSON.toDart),
    },
  };

  final res = await httpPost(
      "/webauthn/register/finish",
      {
        "username": username,
        "state": state,
      },
      obj);
  return res["message"];
}

class RegistrationView extends StatefulWidget {
  const RegistrationView({super.key});

  @override
  State<RegistrationView> createState() => _RegistrationViewState();
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
                      String message = "";
                      try {
                        final username = userCtrl.text;
                        final (state, cred) = await createCredential(username);
                        if (cred == null) {
                          throw Exception("Failed to acquire credentials.");
                        }
                        message = await postAttestationResponse(
                            cred, state, username);
                      } catch (e) {
                        if (e.toString().contains("AbortError")) {
                          return;
                        }
                        message = e.toString();
                      } finally {
                        _webauthnState.notifyRestart();
                        setState(() {
                          regStatus = message;
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

Future<(String, web.PublicKeyCredential?)> getCredential(
    [String username = ""]) async {
  final state = _uuid.v4();
  var params = {"state": state};
  if (username.isNotEmpty) {
    params["username"] = username;
  }

  final res = await httpPost("/webauthn/login/begin", params, null);

  Map<String, dynamic> publicKey = res as Map<String, dynamic>;

  final challenge = publicKey["challenge"];
  publicKey["challenge"] = str2buffer(challenge);

  if (publicKey.keys.contains("allowCredentials")) {
    var allowedcreds = publicKey["allowCredentials"] as List;
    for (int i = 0; i < allowedcreds.length; i++) {
      final cid = allowedcreds[i]["id"];
      allowedcreds[i]["id"] = str2buffer(cid);
    }
    publicKey["allowCredentials"] = allowedcreds;
  }

  final jsPublicKeyOpts = publicKey.jsify();
  final signal = _webauthnState.renewSignal();
  final options = username.isNotEmpty
      ? web.CredentialRequestOptions(
          publicKey: jsPublicKeyOpts as web.PublicKeyCredentialRequestOptions,
          signal: signal)
      : web.CredentialRequestOptions(
          publicKey: jsPublicKeyOpts as web.PublicKeyCredentialRequestOptions,
          mediation: 'conditional',
          signal: signal);

  final credential = await web.window.navigator.credentials.get(options).toDart
      as web.PublicKeyCredential?;
  return (state, credential);
}

Future<String> postSignedAuthResponse(
    web.PublicKeyCredential credential, String state,
    [String username = ""]) async {
  final response = credential.response as web.AuthenticatorAssertionResponse;
  final obj = {
    "id": credential.id,
    "rawId": buffer2str(credential.rawId.toDart),
    "type": 'public-key',
    "response": {
      "authenticatorData": buffer2str(response.authenticatorData.toDart),
      "signature": buffer2str(response.signature.toDart),
      "clientDataJson": buffer2str(response.clientDataJSON.toDart),
      "userHandle": buffer2str(response.userHandle!.toDart),
    },
  };

  var params = {"state": state};
  if (username.isNotEmpty) {
    params["username"] = username;
  }
  final res = await httpPost("/webauthn/login/finish", params, obj);
  debugPrint(res.toString());
  return res["message"];
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
                      String message = "";
                      try {
                        final (state, credential) =
                            await getCredential(userCtrl.text);
                        if (credential == null) {
                          throw Exception("Failed to acquire credentials.");
                        }
                        message = await postSignedAuthResponse(
                            credential, state, userCtrl.text);
                      } catch (e) {
                        if (e.toString().contains("AbortError")) {
                          return;
                        }
                        message = e.toString();
                      } finally {
                        _webauthnState.notifyRestart();
                        setState(() {
                          authStatus = message;
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

class DiscoverPasskeyAuthenticationView extends StatefulWidget {
  const DiscoverPasskeyAuthenticationView({super.key});

  @override
  State<DiscoverPasskeyAuthenticationView> createState() =>
      _DiscoverPasskeyAuthenticationViewState();
}

class _DiscoverPasskeyAuthenticationViewState
    extends State<DiscoverPasskeyAuthenticationView> {
  final TextEditingController userCtrl = TextEditingController();
  String authStatus = "";

  @override
  void initState() {
    super.initState();
    backgroundConditionalAutoComplete();
  }

  @override
  void dispose() {
    userCtrl.dispose();
    super.dispose();
  }

  Future<void> backgroundConditionalAutoComplete() async {
    String status = "";
    try {
      final (state, cred) = await getCredential();
      if (cred != null) {
        debugPrint("Passkey selected! Credential ID: ${cred.id}");
        status = await postSignedAuthResponse(cred, state);
      }
    } catch (e) {
      if (e.toString().contains("AbortError")) {
        return;
      }
      status = e.toString();
    }
    debugPrint("status: $status");
    setState(() {
      authStatus = status;
    });
  }

  @override
  Widget build(BuildContext context) {
    return Column(
      children: [
        const Text("Passkey Authentication View"),
        padding,
        SizedBox(
          width: 300,
          height: 50,
          child: HtmlElementView.fromTagName(
            tagName: 'input',
            onElementCreated: (Object element) {
              final inputElement = element as web.HTMLInputElement;

              inputElement
                ..type = 'text'
                ..id = 'username-field'
                ..autocomplete = 'username webauthn'
                ..placeholder = 'Username or Passkey'
                ..onInput.listen((event) {
                  userCtrl.text = inputElement.value;
                });

              inputElement.style
                ..width = '100%'
                ..height = '100%'
                ..borderBottom = '1px solid #ccc'
                ..borderRadius = '4px'
                ..padding = '8px'
                ..boxSizing = 'border-box';

              // Wait a microtask for Flutter to mount the parent container wrapper,
              // then strip any conflicting aria-hidden tags from ancestors.
              Future.microtask(() {
                web.HTMLElement? parent =
                    inputElement.parentElement as web.HTMLElement?;
                while (parent != null) {
                  if (parent.getAttribute('aria-hidden') == 'true') {
                    parent.removeAttribute(
                        'aria-hidden'); // Force remove the restriction
                  }
                  parent = parent.parentElement as web.HTMLElement?;
                }
              });
            },
          ),
        ),
        ValueListenableBuilder(
          valueListenable: _webauthnState,
          builder: (context, actrl, child) {
            backgroundConditionalAutoComplete();
            return child!;
          },
          child: padding,
        ),
        ValueListenableBuilder(
          valueListenable: userCtrl,
          builder: (context, uctrl, child) {
            return ElevatedButton(
              onPressed: uctrl.text.isEmpty
                  ? null
                  : () async {
                      String message = "";
                      try {
                        final (state, credential) =
                            await getCredential(userCtrl.text);
                        if (credential == null) {
                          throw Exception("Failed to acquire credentials.");
                        }
                        message = await postSignedAuthResponse(
                            credential, state, userCtrl.text);
                      } catch (e) {
                        if (e.toString().contains("AbortError")) {
                          return;
                        }
                        message = e.toString();
                      } finally {
                        _webauthnState.notifyRestart();
                        setState(() {
                          authStatus = message;
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
