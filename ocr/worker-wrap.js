/* Serves kor.traineddata from a base64 text file, because the artifact host does not serve .gz files. */
(function(){
  var realFetch = self.fetch.bind(self);
  var RE = /kor\.traineddata(\.gz)?(\?.*)?$/;
  self.fetch = function(url, opts){
    var u = String(url && url.url ? url.url : url);
    if(!RE.test(u)) return realFetch(url, opts);
    return realFetch(u.replace(RE, "kor-traineddata-gz.b64.txt")).then(function(r){
      if(!r.ok) return r;
      return r.text().then(function(t){
        var bin = atob(t.trim()), a = new Uint8Array(bin.length);
        for(var i=0;i<bin.length;i++) a[i] = bin.charCodeAt(i);
        return new Response(a, {status:200});
      });
    });
  };
  importScripts("worker.min.js");
})();
