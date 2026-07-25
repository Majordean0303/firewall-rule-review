import os
import re
import urllib.request

def download_file(url, dest):
    print(f"Downloading {url} to {dest}...")
    req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
    with urllib.request.urlopen(req) as response, open(dest, 'wb') as out_file:
        out_file.write(response.read())

def process_css(css_path, css_url):
    with open(css_path, 'r', encoding='utf-8') as f:
        css = f.read()
    
    # Find all url(...)
    urls = re.findall(r'url\((.*?)\)', css)
    for u in urls:
        clean_u = u.strip('\'"')
        if clean_u.startswith('data:'): continue
        
        # Resolve absolute URL
        if clean_u.startswith('http'):
            font_url = clean_u
        elif clean_u.startswith('//'):
            font_url = 'https:' + clean_u
        else:
            base_url = css_url.rsplit('/', 1)[0]
            clean_rel = clean_u.lstrip('./')
            font_url = f"{base_url}/{clean_rel}"
            
        font_name = os.path.basename(clean_u.split('?')[0].split('#')[0])
        font_dest = os.path.join('static', 'fonts', font_name)
        
        if not os.path.exists(font_dest):
            try:
                download_file(font_url, font_dest)
            except Exception as e:
                print(f"Failed to download font {font_url}: {e}")
                continue
                
        # Replace in CSS
        css = css.replace(u, f"'../fonts/{font_name}'")
        
    with open(css_path, 'w', encoding='utf-8') as f:
        f.write(css)

def main():
    os.makedirs('static/css', exist_ok=True)
    os.makedirs('static/js', exist_ok=True)
    os.makedirs('static/fonts', exist_ok=True)
    
    assets = {
        'js': [
            'https://code.jquery.com/jquery-3.7.0.min.js',
            'https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js',
            'https://cdn.datatables.net/1.13.6/js/jquery.dataTables.min.js',
            'https://cdn.datatables.net/1.13.6/js/dataTables.bootstrap5.min.js'
        ],
        'css': [
            'https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap',
            'https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css',
            'https://cdn.datatables.net/1.13.6/css/dataTables.bootstrap5.min.css',
            'https://cdn.jsdelivr.net/npm/bootstrap-icons@1.10.5/font/bootstrap-icons.css'
        ]
    }
    
    replacements = {}
    
    for url in assets['js']:
        name = os.path.basename(url.split('?')[0])
        dest = os.path.join('static', 'js', name)
        if not os.path.exists(dest): download_file(url, dest)
        replacements[url] = f"{{{{ url_for('static', filename='js/{name}') }}}}"
        
    for url in assets['css']:
        name = os.path.basename(url.split('?')[0])
        if name == 'css2': name = 'inter.css'
        dest = os.path.join('static', 'css', name)
        if not os.path.exists(dest):
            download_file(url, dest)
            process_css(dest, url)
        replacements[url] = f"{{{{ url_for('static', filename='css/{name}') }}}}"
        
    # Remove the preconnects completely
    removals = [
        '<link rel="preconnect" href="https://fonts.googleapis.com">',
        '<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>'
    ]
    
    # Update HTML templates
    for html_file in ['templates/index.html', 'templates/summary.html']:
        with open(html_file, 'r', encoding='utf-8') as f:
            content = f.read()
            
        for old_url, new_url in replacements.items():
            content = content.replace(old_url, new_url)
            
        for r in removals:
            content = content.replace(r, '')
            
        with open(html_file, 'w', encoding='utf-8') as f:
            f.write(content)
            
    print("All assets downloaded and templates updated!")

if __name__ == '__main__':
    main()
