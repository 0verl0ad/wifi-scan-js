//Coded by J.M. Fernández (The X-C3LL)
// http://0verl0ad.blogspot.com
// http://twitter.com/T



var pcap = require("pcap");
var http = require("http");



var AP = [];
var APh = [];
var pReq = [];

function probeRequest(shost) {
	this.shost = shost;
	this.bssid = "";
	this.essid = "";
}

function red (essid) {
	this.essid = essid;
	this.mac = "";
	this.assoc = [];
}

function hex2a(value) {
    var hex = value.toString();//force conversion
    var str = '';
    for (var i = 0; i < hex.length; i += 2)
        str += String.fromCharCode(parseInt(hex.substr(i, 2), 16));
    return str;
}

function extract_ESSID(packet) {
	var hex = packet.toString("hex");
	var start = hex.search("10400");
	start = start + 5;
	var length = parseInt(hex.substr(126, 2), 16).toString(10);
	length = length * 2;
	start = start + 2;
	var ESSID = hex.substr(start, length);
	return hex2a(ESSID);
}


var server = http.createServer(function (request, response) {
	response.writeHead(200, {"Content-Type" : "text/html" });
	response.write("<body style='background-color: black; color: lime;'>");
	response.write("<center><h1>Simple Wifi Scan in JS</h1></center>")
	response.write("<h2> Beacons & Probe-Response frames correlated with RTS frames</h2><br>");
	for (i = 0; i < AP.length; i++) {
		response.write("<b>AP Detected: </b>"+ AP[i].essid + " [" + AP[i].mac + "]    <b>Stations associated:</b>   ");
		for (j = 0; j < AP[i].assoc.length; j++) {
			response.write("     " + AP[i].assoc[j] + " ");
		}
	response.write("</br>");
	}
	response.write("</br>");
	response.end();
});
server.listen(777);


pcap.createSession("mon0", '(type mgt subtype beacon) or (type mgt subtype probe-resp ) or (type ctl subtype rts ) or (type mgt subtype probe-req )').
on('packet', function (raw_packet) {
with(pcap.decode.packet(raw_packet).link.ieee802_11Frame)
if (type == 0 && subType == 5) {
	var ESSID = extract_ESSID(raw_packet);
	if (APh.indexOf(ESSID) === -1) {
	var ap = new red(ESSID);
	ap.mac = shost;
	AP.push(ap);
	APh.push(ESSID);
	console.log(ESSID + "- Beacon" + ap.mac + "_" + AP.length);
	}
	
} else if (type == 0 && subType == 8) {
	var ESSID = extract_ESSID(raw_packet);
	if (APh.indexOf(ESSID) === -1) {
	var ap = new red(ESSID);
	ap.mac = shost;
	AP.push(ap);
	APh.push(ESSID);
	console.log(ESSID + "- Beacon" + ap.mac+ "_" + AP.length);
	}
} else if (type == 1 && subType == 11) {

	if (AP.length > 0) {
		for (i = 0; i < AP.length; i++) {
			var check = 1;
			if (shost === AP[i].mac) {
				var check = bssid;
			}
			if (bssid === AP[i].mac) {
				var check = shost;
			}
			if (check != 1) {
				if (AP[i].assoc.indexOf(check) === -1) {
					AP[i].assoc.push(check);
				}
			}
		}
	}
} 
});


