

// @ts-ignore
import { connect } from 'cloudflare:sockets';

// Generate your own UUID using the following command in PowerShell:
// Powershell -NoExit -Command "[guid]::NewGuid()"
let userID = '18c45807-c887-4ff7-8a35-82b7dc3d7b2b';

let proxyPort = 443;

let socks5Enable = false;
let parsedSocks5 = {};

// https://cloudflare-dns.com/dns-query or https://dns.google/dns-query
// DNS-over-HTTPS URL
let dohURL = 'https://sky.rethinkdns.com/1:-Pf_____9_8A_AMAIgE8kMABVDDmKOHTAKg=';


// Network protocol type
let network = 'ws'; // WebSocket





if (!isValidUUID(userID)) {
	throw new Error('uuid is invalid');
}

export default {
	/**
	 * @param {import("@cloudflare/workers-types").Request} request
	 * @param {} env
	 * @param {import("@cloudflare/workers-types").ExecutionContext} ctx
	 * @returns {Promise<Response>}
	 */
	async fetch(request, env, ctx) {
		try {
			//const uuid = url.searchParams.get('uuid')?.toLowerCase() || 'null';
			const ua = request.headers.get('User-Agent') || 'null';
			const userAgent = ua.toLowerCase();
			const host = request.headers.get('Host');
			const upgradeHeader = request.headers.get('Upgrade');

			// If WebSocket upgrade, handle WebSocket request
			if (upgradeHeader === 'websocket') {
				return await vlessOverWSHandler(request);
			}


			const vlessConfig = await getVLESSConfig(userID, host, userAgent);
			const isMozilla = userAgent.includes('mozilla');
			// Prepare common headers
			const commonHeaders = {
				"Content-Type": isMozilla ? "text/html;charset=utf-8" : "text/plain;charset=utf-8",
			};

			return new Response(vlessConfig, {
				status: 200,
				headers: commonHeaders,
			});

		} catch (err) {
			// Log error for debugging purposes
			console.error('Error processing request:', err);
			return new Response(`Error: ${err.message}`, { status: 500 });
		}
	},
};


/** ---------------------Tools------------------------------ */

export async function hashHex_f(string) {
	const encoder = new TextEncoder();
	const data = encoder.encode(string);
	const hashBuffer = await crypto.subtle.digest('SHA-256', data);
	const hashArray = Array.from(new Uint8Array(hashBuffer));
	const hashHex = hashArray.map(byte => byte.toString(16).padStart(2, '0')).join('');
	return hashHex;
}

/**
 * Checks if a given string is a valid UUID.
 * Note: This is not a real UUID validation.
 * @param {string} uuid The string to validate as a UUID.
 * @returns {boolean} True if the string is a valid UUID, false otherwise.
 */
function isValidUUID(uuid) {
	const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[4][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
	return uuidRegex.test(uuid);
}

const byteToHex = [];
for (let i = 0; i < 256; ++i) {
	byteToHex.push((i + 256).toString(16).slice(1));
}

function unsafeStringify(arr, offset = 0) {
	return (byteToHex[arr[offset + 0]] + byteToHex[arr[offset + 1]] + byteToHex[arr[offset + 2]] + byteToHex[arr[offset + 3]] + "-" + byteToHex[arr[offset + 4]] + byteToHex[arr[offset + 5]] + "-" + byteToHex[arr[offset + 6]] + byteToHex[arr[offset + 7]] + "-" + byteToHex[arr[offset + 8]] + byteToHex[arr[offset + 9]] + "-" + byteToHex[arr[offset + 10]] + byteToHex[arr[offset + 11]] + byteToHex[arr[offset + 12]] + byteToHex[arr[offset + 13]] + byteToHex[arr[offset + 14]] + byteToHex[arr[offset + 15]]).toLowerCase();
}

function stringify(arr, offset = 0) {
	const uuid = unsafeStringify(arr, offset);
	if (!isValidUUID(uuid)) {
		throw TypeError("Stringified UUID is invalid");
	}
	return uuid;
}

/**
 * Decodes a base64 string into an ArrayBuffer.
 * @param {string} base64Str The base64 string to decode.
 * @returns {{earlyData: ArrayBuffer|null, error: Error|null}} An object containing the decoded ArrayBuffer or null if there was an error, and any error that occurred during decoding or null if there was no error.
 */
function base64ToArrayBuffer(base64Str) {
	if (!base64Str) {
		return { earlyData: null, error: null };
	}
	try {
		// go use modified Base64 for URL rfc4648 which js atob not support
		base64Str = base64Str.replace(/-/g, '+').replace(/_/g, '/');
		const decode = atob(base64Str);
		const arryBuffer = Uint8Array.from(decode, (c) => c.charCodeAt(0));
		return { earlyData: arryBuffer.buffer, error: null };
	} catch (error) {
		return { earlyData: null, error };
	}
}





/** ---------------------Get data------------------------------ */


/**
 * @param {string} userID
 * @param {string | null} host
 * @param {string} userAgent
 * @param {string} _url
 * @returns {Promise<string>}
 */
async function getVLESSConfig(userID, host, userAgent) {
	userAgent = userAgent.toLowerCase();
	let port = 443;
	const v2ray = getConfigLink(userID, host, host, port, host);
	if (userAgent.includes('mozilla')) {
		return getConfigHtml(v2ray);
	}
}

const protocolTypeBase64 = 'dmxlc3M=';
/**
 * Get node configuration information
 * @param {*} uuid
 * @param {*} host
 * @param {*} address
 * @param {*} port
 * @param {*} remarks
 * @returns
 */
function getConfigLink(uuid, host, address, port, remarks) {
	const protocolType = atob(protocolTypeBase64);
	const encryption = 'none';
	let path = '/?ed=2560';
	const fingerprint = 'randomized';
	let tls = ['tls', true];
	const v2ray = getV2rayLink({ protocolType, host, uuid, address, port, remarks, encryption, path, fingerprint, tls });
	return v2ray;
}

/**
 * Get vless information
 * @param {*} param0
 * @returns
 */
function getV2rayLink({ protocolType, host, uuid, address, port, remarks, encryption, path, fingerprint, tls }) {
	let sniAndFp = `&sni=${host}&fp=${fingerprint}`;
	if (portSet_http.has(parseInt(port))) {
		tls = ['', false];
		sniAndFp = '';
	}

	const v2rayLink = `${protocolType}://${uuid}@${address}:${port}?encryption=${encryption}&security=${tls[0]}&type=${network}&host=${host}&path=${encodeURIComponent(path)}${sniAndFp}#${encodeURIComponent(remarks)}`;
	return v2rayLink;
}

/**
 * Generate home page
 * @param {*} v2ray

 * @returns
 */
function getConfigHtml(v2ray) {
	// HTML Head with CSS and FontAwesome library
	const htmlHead = `
    <head>
      <title>simple-cf</title>
      <meta name='description' content='This is a project to generate free vmess nodes. For more information, please subscribe youtube(AM科技) https://youtube.com/@AM_CLUB and follow GitHub https://github.com/amclubs ' />
      <style>
        body {
          font-family: Arial, sans-serif;
          background-color: #f0f0f0;
          color: #333;
          padding: 0;
          margin: 0;
        }
        a {
          color: #1a0dab;
          text-decoration: none;
        }
        img {
          max-width: 100%;
          height: auto;
        }
        pre {
          white-space: pre-wrap;
          word-wrap: break-word;
          background-color: #fff;
          border: 1px solid #ddd;
          padding: 10px;
          margin: 0;
        }
        /* Dark mode */
        @media (prefers-color-scheme: dark) {
          body {
            background-color: #333;
            color: #f0f0f0;
          }
          a {
            color: #9db4ff;
          }
          pre {
            background-color: #282a36;
            border-color: #6272a4;
          }
        }
      </style>
    </head>
  `;


	const output = `

################################################################
v2ray： <button onclick='copyToClipboard("${v2ray}")'><i class="fa fa-clipboard"></i> 点击复制v2ray信息 </button>
---------------------------------------------------------------
${v2ray}
---------------------------------------------------------------
################################################################
  `;

	// Final HTML
	const html = `
<html>
${htmlHead}
<body>
  <pre>${output}</pre>
  <script>
    function copyToClipboard(text) {
      navigator.clipboard.writeText(text)
        .then(() => {
          alert("Copied to clipboard");
        })
        .catch(err => {
          console.error("Failed to copy to clipboard:", err);
        });
    }
  </script>
</body>
</html>
  `;

	return html;
}


let portSet_http = new Set([80, 8080, 8880, 2052, 2086, 2095, 2082]);


/** -------------------processing logic-------------------------------- */
/**
 * Handles VLESS over WebSocket requests by creating a WebSocket pair, accepting the WebSocket connection, and processing the VLESS header.
 * @param {import("@cloudflare/workers-types").Request} request The incoming request object.
 * @returns {Promise<Response>} A Promise that resolves to a WebSocket response object.
 */
async function vlessOverWSHandler(request) {
	const webSocketPair = new WebSocketPair();
	const [client, webSocket] = Object.values(webSocketPair);
	webSocket.accept();

	let address = '';
	let portWithRandomLog = '';
	let currentDate = new Date();
	const log = (/** @type {string} */ info, /** @type {string | undefined} */ event) => {
		console.log(`[${currentDate} ${address}:${portWithRandomLog}] ${info}`, event || '');
	};
	const earlyDataHeader = request.headers.get('sec-websocket-protocol') || '';
	const readableWebSocketStream = makeReadableWebSocketStream(webSocket, earlyDataHeader, log);

	/** @type {{ value: import("@cloudflare/workers-types").Socket | null}}*/
	let remoteSocketWapper = {
		value: null,
	};
	let udpStreamWrite = null;
	let isDns = false;

	// ws --> remote
	readableWebSocketStream.pipeTo(new WritableStream({
		async write(chunk, controller) {
			if (isDns && udpStreamWrite) {
				return udpStreamWrite(chunk);
			}
			if (remoteSocketWapper.value) {
				const writer = remoteSocketWapper.value.writable.getWriter()
				await writer.write(chunk);
				writer.releaseLock();
				return;
			}

			const {
				hasError,
				//message,
				portRemote = 443,
				addressRemote = '',
				rawDataIndex,
				vlessVersion = new Uint8Array([0, 0]),
				isUDP,
				addressType,
			} = processVlessHeader(chunk, userID);
			address = addressRemote;
			portWithRandomLog = `${portRemote} ${isUDP ? 'udp' : 'tcp'} `;

			if (hasError) {
				throw new Error(message);
			}

			// If UDP and not DNS port, close it
			if (isUDP && portRemote !== 53) {
				throw new Error('UDP proxy only enabled for DNS which is port 53');
			}

			if (isUDP && portRemote === 53) {
				isDns = true;
			}

			const vlessResponseHeader = new Uint8Array([vlessVersion[0], 0]);
			const rawClientData = chunk.slice(rawDataIndex);

			if (isDns) {
				const { write } = await handleUDPOutBound(webSocket, vlessResponseHeader, log);
				udpStreamWrite = write;
				udpStreamWrite(rawClientData);
				return;
			}
			log(`processVlessHeader-->${addressType} Processing TCP outbound connection ${addressRemote}:${portRemote}`);

			handleTCPOutBound(remoteSocketWapper, addressRemote, portRemote, rawClientData, webSocket, vlessResponseHeader, log, addressType);
		},
		close() {
			log(`readableWebSocketStream is close`);
		},
		abort(reason) {
			log(`readableWebSocketStream is abort`, JSON.stringify(reason));
		},
	})).catch((err) => {
		log('readableWebSocketStream pipeTo error', err);
	});

	return new Response(null, {
		status: 101,
		webSocket: client,
	});
}

/**
 * Handles outbound TCP connections.
 *
 * @param {any} remoteSocket
 * @param {string} addressRemote The remote address to connect to.
 * @param {number} portRemote The remote port to connect to.
 * @param {Uint8Array} rawClientData The raw client data to write.
 * @param {import("@cloudflare/workers-types").WebSocket} webSocket The WebSocket to pass the remote socket to.
 * @param {Uint8Array} vlessResponseHeader The VLESS response header.
 * @param {function} log The logging function.
 * @returns {Promise<void>} The remote socket.
 */
async function handleTCPOutBound(remoteSocket, addressRemote, portRemote, rawClientData, webSocket, vlessResponseHeader, log, addressType,) {

	/**
	 * Connects to a given address and port and writes data to the socket.
	 * @param {string} address The address to connect to.
	 * @param {number} port The port to connect to.
	 * @returns {Promise<import("@cloudflare/workers-types").Socket>} A Promise that resolves to the connected socket.
	 */
	async function connectAndWrite(address, port, socks = false) {
		/** @type {import("@cloudflare/workers-types").Socket} */
		const tcpSocket = socks ? await socks5Connect(addressType, address, port, log)
			: connect({
				hostname: address,
				port: port,
			});
		remoteSocket.value = tcpSocket;
		console.log(`connectAndWrite-${socks} connected to ${address}:${port}`);
		const writer = tcpSocket.writable.getWriter();
		await writer.write(rawClientData);
		writer.releaseLock();
		return tcpSocket;
	}

	/**
	 * Retries connecting to the remote address and port if the Cloudflare socket has no incoming data.
	 * @returns {Promise<void>} A Promise that resolves when the retry is complete.
	 */
	async function retry() {
		const tcpSocket = socks5Enable ? await connectAndWrite(addressRemote, portRemote, true) : await connectAndWrite(addressRemote, proxyPort || portRemote);

		console.log(`retry-${socks5Enable} connected to ${addressRemote}:${portRemote}`);
		tcpSocket.closed.catch(error => {
			console.log('retry tcpSocket closed error', error);
		}).finally(() => {
			safeCloseWebSocket(webSocket);
		})
		remoteSocketToWS(tcpSocket, webSocket, vlessResponseHeader, null, log);
	}

	const tcpSocket = await connectAndWrite(addressRemote, portRemote);

	// when remoteSocket is ready, pass to websocket
	// remote--> ws
	remoteSocketToWS(tcpSocket, webSocket, vlessResponseHeader, retry, log);
}

/**
 * Creates a readable stream from a WebSocket server, allowing for data to be read from the WebSocket.
 * @param {import("@cloudflare/workers-types").WebSocket} webSocketServer The WebSocket server to create the readable stream from.
 * @param {string} earlyDataHeader The header containing early data for WebSocket 0-RTT.
 * @param {(info: string)=> void} log The logging function.
 * @returns {ReadableStream} A readable stream that can be used to read data from the WebSocket.
 */
function makeReadableWebSocketStream(webSocketServer, earlyDataHeader, log) {
	let readableStreamCancel = false;
	const stream = new ReadableStream({
		start(controller) {
			webSocketServer.addEventListener('message', (event) => {
				const message = event.data;
				controller.enqueue(message);
			});

			webSocketServer.addEventListener('close', () => {
				safeCloseWebSocket(webSocketServer);
				controller.close();
			});

			webSocketServer.addEventListener('error', (err) => {
				log('webSocketServer has error');
				controller.error(err);
			});
			const { earlyData, error } = base64ToArrayBuffer(earlyDataHeader);
			if (error) {
				controller.error(error);
			} else if (earlyData) {
				controller.enqueue(earlyData);
			}
		},

		pull(controller) {
			// if ws can stop read if stream is full, we can implement backpressure
			// https://streams.spec.whatwg.org/#example-rs-push-backpressure
		},

		cancel(reason) {
			log(`ReadableStream was canceled, due to ${reason}`)
			readableStreamCancel = true;
			safeCloseWebSocket(webSocketServer);
		}
	});

	return stream;
}

// https://xtls.github.io/development/protocols/vless.html

/**
 * Processes the VLESS header buffer and returns an object with the relevant information.
 * @param {ArrayBuffer} vlessBuffer The VLESS header buffer to process.
 * @param {string} userID The user ID to validate against the UUID in the VLESS header.
 * @returns {{
 *  hasError: boolean,
 *  message?: string,
 *  addressRemote?: string,
 *  addressType?: number,
 *  portRemote?: number,
 *  rawDataIndex?: number,
 *  vlessVersion?: Uint8Array,
 *  isUDP?: boolean
 * }} An object with the relevant information extracted from the VLESS header buffer.
 */
function processVlessHeader(vlessBuffer, userID) {
	if (vlessBuffer.byteLength < 24) {
		return {
			hasError: true,
			message: 'invalid data',
		};
	}

	const version = new Uint8Array(vlessBuffer.slice(0, 1));
	let isValidUser = false;
	let isUDP = false;
	const slicedBuffer = new Uint8Array(vlessBuffer.slice(1, 17));
	const slicedBufferString = stringify(slicedBuffer);
	// check if userID is valid uuid or uuids split by , and contains userID in it otherwise return error message to console
	const uuids = userID.includes(',') ? userID.split(",") : [userID];
	// uuid_validator(hostName, slicedBufferString);


	// isValidUser = uuids.some(userUuid => slicedBufferString === userUuid.trim());
	isValidUser = uuids.some(userUuid => slicedBufferString === userUuid.trim()) || uuids.length === 1 && slicedBufferString === uuids[0].trim();

	console.log(`userID: ${slicedBufferString}`);

	if (!isValidUser) {
		return {
			hasError: true,
			message: 'invalid user',
		};
	}

	const optLength = new Uint8Array(vlessBuffer.slice(17, 18))[0];
	//skip opt for now

	const command = new Uint8Array(
		vlessBuffer.slice(18 + optLength, 18 + optLength + 1)
	)[0];

	// 0x01 TCP
	// 0x02 UDP
	// 0x03 MUX
	if (command === 1) {
		isUDP = false;
	} else if (command === 2) {
		isUDP = true;
	} else {
		return {
			hasError: true,
			message: `command ${command} is not support, command 01-tcp,02-udp,03-mux`,
		};
	}
	const portIndex = 18 + optLength + 1;
	const portBuffer = vlessBuffer.slice(portIndex, portIndex + 2);
	// port is big-Endian in raw data etc 80 == 0x005d
	const portRemote = new DataView(portBuffer).getUint16(0);

	let addressIndex = portIndex + 2;
	const addressBuffer = new Uint8Array(
		vlessBuffer.slice(addressIndex, addressIndex + 1)
	);

	// 1--> ipv4  addressLength =4
	// 2--> domain name addressLength=addressBuffer[1]
	// 3--> ipv6  addressLength =16
	const addressType = addressBuffer[0];
	let addressLength = 0;
	let addressValueIndex = addressIndex + 1;
	let addressValue = '';
	switch (addressType) {
		case 1:
			addressLength = 4;
			addressValue = new Uint8Array(
				vlessBuffer.slice(addressValueIndex, addressValueIndex + addressLength)
			).join('.');
			break;
		case 2:
			addressLength = new Uint8Array(
				vlessBuffer.slice(addressValueIndex, addressValueIndex + 1)
			)[0];
			addressValueIndex += 1;
			addressValue = new TextDecoder().decode(
				vlessBuffer.slice(addressValueIndex, addressValueIndex + addressLength)
			);
			break;
		case 3:
			addressLength = 16;
			const dataView = new DataView(
				vlessBuffer.slice(addressValueIndex, addressValueIndex + addressLength)
			);
			// 2001:0db8:85a3:0000:0000:8a2e:0370:7334
			const ipv6 = [];
			for (let i = 0; i < 8; i++) {
				ipv6.push(dataView.getUint16(i * 2).toString(16));
			}
			addressValue = ipv6.join(':');
			// seems no need add [] for ipv6
			break;
		default:
			return {
				hasError: true,
				message: `invild  addressType is ${addressType}`,
			};
	}
	if (!addressValue) {
		return {
			hasError: true,
			message: `addressValue is empty, addressType is ${addressType}`,
		};
	}

	return {
		hasError: false,
		addressRemote: addressValue,
		portRemote,
		rawDataIndex: addressValueIndex + addressLength,
		vlessVersion: version,
		isUDP,
		addressType,
	};
}

/**
 * Converts a remote socket to a WebSocket connection.
 * @param {import("@cloudflare/workers-types").Socket} remoteSocket The remote socket to convert.
 * @param {import("@cloudflare/workers-types").WebSocket} webSocket The WebSocket to connect to.
 * @param {ArrayBuffer | null} vlessResponseHeader The VLESS response header.
 * @param {(() => Promise<void>) | null} retry The function to retry the connection if it fails.
 * @param {(info: string) => void} log The logging function.
 * @returns {Promise<void>} A Promise that resolves when the conversion is complete.
 */
async function remoteSocketToWS(remoteSocket, webSocket, vlessResponseHeader, retry, log) {
	// remote--> ws
	let remoteChunkCount = 0;
	let chunks = [];
	/** @type {ArrayBuffer | null} */
	let vlessHeader = vlessResponseHeader;
	let hasIncomingData = false; // check if remoteSocket has incoming data
	await remoteSocket.readable
		.pipeTo(
			new WritableStream({
				start() {
				},
				/**
				 *
				 * @param {Uint8Array} chunk
				 * @param {*} controller
				 */
				async write(chunk, controller) {
					hasIncomingData = true;
					remoteChunkCount++;
					if (webSocket.readyState !== WS_READY_STATE_OPEN) {
						controller.error(
							'webSocket.readyState is not open, maybe close'
						);
					}
					if (vlessHeader) {
						webSocket.send(await new Blob([vlessHeader, chunk]).arrayBuffer());
						vlessHeader = null;
					} else {
						// console.log(`remoteSocketToWS send chunk ${chunk.byteLength}`);
						// seems no need rate limit this, CF seems fix this??..
						// if (remoteChunkCount > 20000) {
						// 	// cf one package is 4096 byte(4kb),  4096 * 20000 = 80M
						// 	await delay(1);
						// }
						webSocket.send(chunk);
					}
				},
				close() {
					log(`remoteConnection!.readable is close with hasIncomingData is ${hasIncomingData}`);
					// safeCloseWebSocket(webSocket); // no need server close websocket frist for some case will casue HTTP ERR_CONTENT_LENGTH_MISMATCH issue, client will send close event anyway.
				},
				abort(reason) {
					console.error(`remoteConnection!.readable abort`, reason);
				},
			})
		)
		.catch((error) => {
			console.error(
				`remoteSocketToWS has exception `,
				error.stack || error
			);
			safeCloseWebSocket(webSocket);
		});

	// seems is cf connect socket have error,
	// 1. Socket.closed will have error
	// 2. Socket.readable will be close without any data coming
	if (hasIncomingData === false && retry) {
		log(`retry`)
		retry();
	}
}

const WS_READY_STATE_OPEN = 1;
const WS_READY_STATE_CLOSING = 2;
/**
 * Closes a WebSocket connection safely without throwing exceptions.
 * @param {import("@cloudflare/workers-types").WebSocket} socket The WebSocket connection to close.
 */
function safeCloseWebSocket(socket) {
	try {
		if (socket.readyState === WS_READY_STATE_OPEN || socket.readyState === WS_READY_STATE_CLOSING) {
			socket.close();
		}
	} catch (error) {
		console.error('safeCloseWebSocket error', error);
	}
}

/**
 * Handles outbound UDP traffic by transforming the data into DNS queries and sending them over a WebSocket connection.
 * @param {import("@cloudflare/workers-types").WebSocket} webSocket The WebSocket connection to send the DNS queries over.
 * @param {ArrayBuffer} vlessResponseHeader The VLESS response header.
 * @param {(string) => void} log The logging function.
 * @returns {{write: (chunk: Uint8Array) => void}} An object with a write method that accepts a Uint8Array chunk to write to the transform stream.
 */
async function handleUDPOutBound(webSocket, vlessResponseHeader, log) {

	let isVlessHeaderSent = false;
	const transformStream = new TransformStream({
		start(controller) {

		},
		transform(chunk, controller) {
			// udp message 2 byte is the the length of udp data
			// TODO: this should have bug, beacsue maybe udp chunk can be in two websocket message
			for (let index = 0; index < chunk.byteLength;) {
				const lengthBuffer = chunk.slice(index, index + 2);
				const udpPakcetLength = new DataView(lengthBuffer).getUint16(0);
				const udpData = new Uint8Array(
					chunk.slice(index + 2, index + 2 + udpPakcetLength)
				);
				index = index + 2 + udpPakcetLength;
				controller.enqueue(udpData);
			}
		},
		flush(controller) {
		}
	});

	// only handle dns udp for now
	transformStream.readable.pipeTo(new WritableStream({
		async write(chunk) {
			const resp = await fetch(dohURL, // dns server url
				{
					method: 'POST',
					headers: {
						'content-type': 'application/dns-message',
					},
					body: chunk,
				})
			const dnsQueryResult = await resp.arrayBuffer();
			const udpSize = dnsQueryResult.byteLength;
			// console.log([...new Uint8Array(dnsQueryResult)].map((x) => x.toString(16)));
			const udpSizeBuffer = new Uint8Array([(udpSize >> 8) & 0xff, udpSize & 0xff]);
			if (webSocket.readyState === WS_READY_STATE_OPEN) {
				log(`doh success and dns message length is ${udpSize}`);
				if (isVlessHeaderSent) {
					webSocket.send(await new Blob([udpSizeBuffer, dnsQueryResult]).arrayBuffer());
				} else {
					webSocket.send(await new Blob([vlessResponseHeader, udpSizeBuffer, dnsQueryResult]).arrayBuffer());
					isVlessHeaderSent = true;
				}
			}
		}
	})).catch((error) => {
		log('dns udp has error' + error)
	});

	const writer = transformStream.writable.getWriter();

	return {
		/**
		 *
		 * @param {Uint8Array} chunk
		 */
		write(chunk) {
			writer.write(chunk);
		}
	};
}

/**
 * Handles outbound UDP traffic by transforming the data into DNS queries and sending them over a WebSocket connection.
 * @param {ArrayBuffer} udpChunk - DNS query data sent from the client.
 * @param {import("@cloudflare/workers-types").WebSocket} webSocket - The WebSocket connection to send the DNS queries over.
 * @param {ArrayBuffer} vlessResponseHeader - The VLESS response header.
 * @param {(string) => void} log - The logging function.
 * @returns {{write: (chunk: Uint8Array) => void}} An object with a write method that accepts a Uint8Array chunk to write to the transform stream.
 */
async function handleDNSQuery(udpChunk, webSocket, vlessResponseHeader, log) {
	try {
		const dnsServer = '8.8.4.4';
		const dnsPort = 53;
		let vlessHeader = vlessResponseHeader;

		const tcpSocket = connect({ hostname: dnsServer, port: dnsPort });
		log(`Connected to ${dnsServer}:${dnsPort}`);

		const writer = tcpSocket.writable.getWriter();
		await writer.write(udpChunk);
		writer.releaseLock();

		await tcpSocket.readable.pipeTo(new WritableStream({
			async write(chunk) {
				if (webSocket.readyState === WS_READY_STATE_OPEN) {
					const dataToSend = vlessHeader ? await new Blob([vlessHeader, chunk]).arrayBuffer() : chunk;
					webSocket.send(dataToSend);
					vlessHeader = null;
				}
			},
			close() {
				log(`TCP connection to DNS server (${dnsServer}) closed`);
			},
			abort(reason) {
				console.error(`TCP connection to DNS server (${dnsServer}) aborted`, reason);
			},
		}));
	} catch (error) {
		console.error(`Exception in handleDNSQuery function: ${error.message}`);
	}
}


async function socks5Connect(ipType, remoteIp, remotePort, log) {
	const { username, password, hostname, port } = parsedSocks5;
	const socket = connect({ hostname, port });
	const writer = socket.writable.getWriter();
	const reader = socket.readable.getReader();
	const encoder = new TextEncoder();

	const sendSocksGreeting = async () => {
		const greeting = new Uint8Array([5, 2, 0, 2]);
		await writer.write(greeting);
		console.log('SOCKS5 greeting sent');
	};

	const handleAuthResponse = async () => {
		const res = (await reader.read()).value;
		if (res[1] === 0x02) {
			console.log("SOCKS5 server requires authentication");
			if (!username || !password) {
				console.log("Please provide username and password");
				throw new Error("Authentication required");
			}
			const authRequest = new Uint8Array([
				1, username.length, ...encoder.encode(username),
				password.length, ...encoder.encode(password)
			]);
			await writer.write(authRequest);
			const authResponse = (await reader.read()).value;
			if (authResponse[0] !== 0x01 || authResponse[1] !== 0x00) {
				console.log("SOCKS5 server authentication failed");
				throw new Error("Authentication failed");
			}
		}
	};

	const sendSocksRequest = async () => {
		let DSTADDR;
		switch (ipType) {
			case 1:
				DSTADDR = new Uint8Array([1, ...remoteIp.split('.').map(Number)]);
				break;
			case 2:
				DSTADDR = new Uint8Array([3, remoteIp.length, ...encoder.encode(remoteIp)]);
				break;
			case 3:
				DSTADDR = new Uint8Array([4, ...remoteIp.split(':').flatMap(x => [
					parseInt(x.slice(0, 2), 16), parseInt(x.slice(2), 16)
				])]);
				break;
			default:
				console.log(`Invalid address type: ${ipType}`);
				throw new Error("Invalid address type");
		}
		const socksRequest = new Uint8Array([5, 1, 0, ...DSTADDR, remotePort >> 8, remotePort & 0xff]);
		await writer.write(socksRequest);
		console.log('SOCKS5 request sent');

		const response = (await reader.read()).value;
		if (response[1] !== 0x00) {
			console.log("SOCKS5 connection failed");
			throw new Error("Connection failed");
		}
		console.log("SOCKS5 connection established");
	};

	try {
		await sendSocksGreeting();
		await handleAuthResponse();
		await sendSocksRequest();
	} catch (error) {
		console.log(error.message);
		return null; // Return null on failure
	} finally {
		writer.releaseLock();
		reader.releaseLock();
	}
	return socket;
}


