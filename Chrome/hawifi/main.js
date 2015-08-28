window.onload = function() {
  document.querySelector('#greeting').innerText =
    'Hello, World! It is ' + new Date();
    console.log("window.onload");
};

var submitButton = document.querySelector('#show');

submitButton.addEventListener('click', function(e) {
  // HMAC_SHA256("key", "The quick brown fox jumps over the lazy dog") = 
  // 0xf7bc83f430538424b13298e6aa6fb143ef4d59a14946175997479dbc2d1a3cd8
  console.log("init");
	var div = document.getElementById("demo");
	var pas = 'password';
	var key = 'key';
  
  var url = 'http://' + document.getElementById("url").value + '/';
  var pat = document.getElementById("cmd").value + '/' + myTime();
  
  var keyb = sjcl.codec.utf8String.toBits(key);
  var beforeHmac = '/' + pas + '/' + pat + '/';
  console.log(beforeHmac);
  var out = (new sjcl.misc.hmac(keyb, sjcl.hash.sha256)).mac(beforeHmac);
  var hmac = sjcl.codec.hex.fromBits(out);
  console.log(hmac);
  pat = pat + '/' + hmac;
  console.log(url + pat);
  
	var xhr = new XMLHttpRequest();

  xhr.onload = function() {
      var result = "status: " + xhr.status + " " + xhr.statusText + "<br />";
      var header = xhr.getAllResponseHeaders();
      var all = header.split("\r\n");
      for (var i = 0; i < all.length; i++) {
          if (all[i] !== "")
              result += ("<li>" + all[i] + "</li>");
      }
	div.innerHTML = xhr.responseText;
  };
  
  //var url = "http://cne02.dynamic.nsn-net.net:8181";
  //var url = "http://www.onet.pl";
  //var url = 'http://192.168.100.149/l1p/' + mT + '/' + hmac;

  xhr.open('GET', url + pat, true);
  xhr.send(null);
    
});

function myTime() {
  return (Date.now() / 1000 | 0) - 1440409855;
}

function doMyRequest(method)
{
    var req = chrome.extension.getBackgroundPage().Request.request;
    req.method = method;
    req.url = document.getElementById("url").value;
    if (req.method == "POST" || req.method == "PUT") {
        //var hash = Sha256.hash("abc");
        //req.body = document.getElementById("content_body").value;
        req.body = Sha256.hash("abc");
    }

    var xhr = new XMLHttpRequest();
    xhr.open(
        req.method,
        req.url,
        false);

    console.log(method + " " + req.url);
    for (var i in req.headers) {
        xhr.setRequestHeader(i, req.headers[i]);
        console.log(i + " " + req.headers[i]);
    }

    xhr.onload = function() {
        var result = "status: " + xhr.status + " " + xhr.statusText + "<br />";
        var header = xhr.getAllResponseHeaders();
        var all = header.split("\r\n");
        for (var i = 0; i < all.length; i++) {
            if (all[i] !== "")
                result += ("<li>" + all[i] + "</li>");
        }

        document.getElementById("response_header").innerHTML = result;
        document.getElementById("response_body").innerText = xhr.responseText;
    };
    xhr.send(req.body);
}


function init()
{
    console.log("init");
    var req = chrome.extension.getBackgroundPage().Request.request;
    req.nameE = document.getElementById("header_name");
    req.valueE = document.getElementById("header_value");
    req.nameE.value = req.hname;
    req.valueE.value = req.hvalue;
    document.getElementById("url").value = req.url;
    document.getElementById("content_body").value = req.body;
    var list = document.getElementById("header_list");
    list.innerHTML = renderHeaders();

    document.getElementById("url").addEventListener("keyup", onUrlChanged);
    document.getElementById("url").addEventListener("blur", onUrlChanged);

    document.getElementById("header_name").addEventListener("keyup", onHeaderChanged);
    document.getElementById("header_name").addEventListener("blur", onHeaderChanged);

    document.getElementById("header_value").addEventListener("keyup", onHeaderChanged);
    document.getElementById("header_value").addEventListener("blur", onHeaderChanged);

    document.getElementById("add_header_button").addEventListener("click", onAddChangeHeader);

    document.getElementById("content_body").addEventListener("keyup", onBodyChanged);
    document.getElementById("content_body").addEventListener("blur", onBodyChanged);

    var methods = ["GET", "POST", "DELETE", "HEAD", "PUT"];
    for (var i=0; i<methods.length;i++) {
        (function(index){
            var button = document.getElementById(methods[i].toLowerCase() + "_request_button");
            button.addEventListener("click", function () {
                doRequest(methods[index]);
            });
        })(i);
    }
}


function onHeaderChanged()
{
    var req = chrome.extension.getBackgroundPage().Request.request;
    req.hname = req.nameE.value;
    req.hvalue = req.valueE.value;
}

function onUrlChanged()
{
    var req = chrome.extension.getBackgroundPage().Request.request;
    req.url = document.getElementById("url").value;
}

function renderHeaders()
{
    var req = chrome.extension.getBackgroundPage().Request.request;
    var html = "<table border=1>";
    html += "<tr><th>name</th><th>value</th></tr>";
    for (var i in req.headers) {
        html += "<tr><td align=\"left\">" + i + "</td><td align=\"right\">" + req.headers[i] + "</td></tr>";
    }
    html += "</table>";
    return html;
}

function onAddChangeHeader()
{
    var req = chrome.extension.getBackgroundPage().Request.request;
    var name = req.nameE.value;
    if (!name) {
        return;
    }
    var value = req.valueE.value;
    if (value == "##") {
        delete req.headers[name];
    } else {
        req.headers[name] = value;
    }
    req.nameE.value = req.valueE.value = "";
    onHeaderChanged();
    var list = document.getElementById("header_list");
    list.innerHTML = renderHeaders();
}

function onBodyChanged()
{
    var req = chrome.extension.getBackgroundPage().Request.request;
    req.body = document.getElementById("content_body").value;
}

function doRequest(method)
{
    var req = chrome.extension.getBackgroundPage().Request.request;
    req.method = method;
    req.url = document.getElementById("url").value;
    if (req.method == "POST" || req.method == "PUT") {
        //var hash = Sha256.hash("abc");
        //req.body = document.getElementById("content_body").value;
        req.body = Sha256.hash("abc");
    }

    var xhr = new XMLHttpRequest();
    xhr.open(
        req.method,
        req.url,
        false);

    console.log(method + " " + req.url);
    for (var i in req.headers) {
        xhr.setRequestHeader(i, req.headers[i]);
        console.log(i + " " + req.headers[i]);
    }

    xhr.onload = function() {
        var result = "status: " + xhr.status + " " + xhr.statusText + "<br />";
        var header = xhr.getAllResponseHeaders();
        var all = header.split("\r\n");
        for (var i = 0; i < all.length; i++) {
            if (all[i] !== "")
                result += ("<li>" + all[i] + "</li>");
        }

        document.getElementById("response_header").innerHTML = result;
        document.getElementById("response_body").innerText = xhr.responseText;
    };
    xhr.send(req.body);
}
