from flask import Flask, render_template, request, redirect, url_for
import subprocess

app = Flask(__name__)

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        from_date = request.form.get('from_date')
        to_date = request.form.get('to_date')
        
        # Make sure these are passed to your script properly
        subprocess.call(['python3', 'HackedSSH.py', '--from_date', from_date, '--to_date', to_date])
        
        # Redirect to the main page with updated data
        return redirect(url_for('index'))
    
    # For GET request, just render the HTML page
    return render_template('HackedSSH.html')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
