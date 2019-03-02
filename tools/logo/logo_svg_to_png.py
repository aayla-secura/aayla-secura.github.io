#!/usr/bin/env python3
import logging
import http.server
import sys
import os
from glob import glob
from socketserver import ThreadingMixIn

logger = logging.getLogger('SVG to PNG converter in our browser')
logger.setLevel(logging.DEBUG)
logger.addHandler(logging.StreamHandler(sys.stdout))

class ThreadingHttpServer(ThreadingMixIn, http.server.HTTPServer):
    pass

class SVGConvertor(http.server.SimpleHTTPRequestHandler):
    _API = '/convert/'
    _defaults = {
            'scale': '2000',
            'bgcol': 'transparent',
            'txtcol': 'white',
            }
    
    def get_param(self, par):
        query = self.path[len(self._API):].partition('?')[2]
        params = dict([v.partition('=')[0::2]
            for v in query.split('&')])
        try:
            return params[par]
        except KeyError:
            pass
        try:
            return self._defaults[par]
        except KeyError:
            return ''

    def convert(self):
        template = '''
<!DOCTYPE html>
<html>
  <head>
    <meta charset="UTF-8" />
    <style type="text/css" media="screen">
      div.svg {{ cursor: pointer; border: grey solid 1px; width: 100px; float: left }}
      object {{ pointer-events: none; width: 100%; }}
      a {{ text-decoration: none; }}
      body {{ background-color: #{bgcol}; color: #{txtcol}; }}
    </style>
    <script charset="utf-8">
      function convert() {{
        var obj = this.querySelector('object');
        var svg = new XMLSerializer().serializeToString(obj.contentDocument.querySelector('svg'));
        var img = document.createElement('img');
        img.src = 'data:image/svg+xml;base64,' + btoa(svg);
        var link = this.querySelector('a');
        img.onload = function () {{
          var cvs = document.createElement('canvas');
          cvs.width = {scale};
          cvs.height = {scale}*img.height/img.width;
          cvs.getContext('2d').drawImage(img, 0, 0);
          link.href = cvs.toDataURL();
          link.onclick = function(e) {{e.stopPropagation();}};
          link.click();
          delete img;
          delete cvs;
          link.href = '#';
        }}
      }}
      function colorize() {{
        var svg = this.contentDocument.querySelector('svg');
        svg.style = 'background-color: #{bgcol}; fill: #{txtcol}';
      }}
    </script>
  </head>
  <body>
    <p>Click on an image do download it as png. Use the scale={{num in px}}
    URL parameter to adjust the size of the png. Use the bgcol={{hex}}
    and txtcol={{hex}} parameters to change the colors (do not prepend
    the color with '#').</p>
    {images}
  </body>
</html>
        '''
        
        cwd = self.path[len(self._API):].split('?',1)[0]
        cwd = cwd.strip('/')

        images = ''
        for fname in glob("{}/*.svg".format(cwd)):
            images += '''
    <div class="svg" id="{name}" onclick="convert.call(this)">
      <a href="#" download="{name}.png"></a>
      <object data="/{img}" onload="colorize.call(this)"></object>
    </div>
            '''.format(img=fname,
                    name=os.path.basename(fname).rsplit('.',1)[0])

        page = template.format(images=images,
                scale=self.get_param('scale'),
                bgcol=self.get_param('bgcol'),
                txtcol=self.get_param('txtcol'))
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.send_header('Content-Length', len(page))
        self.end_headers()
        self.wfile.write(page.encode('utf-8'))

    def do_GET(self):
        if self.path.startswith(self._API):
            self.convert()
        else:
            super().do_GET()

if __name__ == "__main__":
    httpd = ThreadingHttpServer(('127.0.0.1', 58080), SVGConvertor)
    logger.error('''Go to http://127.0.0.1:58080/{api}path/to/svgs in Google Chrome.
Adjust the scale of the png image relative to the width of the svg (100px)'''.format(api=SVGConvertor._API))
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        httpd.socket.close()
