import time
import urllib
import functools
import datetime
from flask import render_template, session, request, redirect, g, current_app, url_for, abort
from adscore.app import app
from adscore import api
from adscore.forms import ModernForm, PaperForm, ClassicForm
from adscore.tools import is_expired

@app.before_request
def before_request():
    """
    Store API anonymous cookie in session or if it exists, check if it has expired
    """
    g.request_start_time = time.time()
    g.request_time = lambda: "{:.3f}s".format((time.time() - g.request_start_time))
    if 'cookies' not in session:
        session['cookies'] = {}
    if request.cookies.get('session'):
        # Re-use BBB session, if it is valid, the same BBB token will be returned by bootstrap
        # thus if the user was authenticated, it will use the user token
        session['cookies']['session'] = request.cookies.get('session')
    if 'auth' not in session or is_expired(session['auth']):
        session['auth'] = api.bootstrap()

@app.errorhandler(404)
def page_not_found(e):
    form = ModernForm(request.args)
    return render_template('404.html', environment=current_app.config['ENVIRONMENT'], base_url=app.config['SERVER_BASE_URL'], auth=session['auth'], request_path=request.path[1:], form=form), 404

@app.route(app.config['SERVER_BASE_URL'], methods=['GET'])
def index():
    """
    Modern form if no search parameters are sent, otherwise show search results
    """
    form = ModernForm(request.args)
    return render_template('modern-form.html', environment=current_app.config['ENVIRONMENT'], base_url=app.config['SERVER_BASE_URL'], auth=session['auth'], form=form)

@app.route(app.config['SERVER_BASE_URL']+'search/<path:params>', methods=['GET'])
@app.route(app.config['SERVER_BASE_URL']+'search/', methods=['GET'])
def search(params=None):
    """
    Modern form if no search parameters are sent, otherwise show search results
    """
    if params:
        # For compatibility with BBB, accept parameters that are embbeded in the
        # URL without a question mark
        parsed = urllib.parse.parse_qs(params)
        # parse_qa will create a list for single strings such as {'q': ['star']},
        # extract them if there is only one element:
        parsed = dict( (k, v if len(v) > 1 else v[0] ) for k, v in parsed.items() )
        # Make sure that numeric parameters are not strings:
        for numeric_param in ('rows', 'start'):
            if numeric_param in parsed:
                try:
                    parsed[numeric_param] = int(parsed[numeric_param])
                except:
                    del parsed[numeric_param]
        form = ModernForm(**parsed)
    else:
        form = ModernForm(request.args)
    if len(form.q.data) > 0:
        results = api.search(form.q.data, rows=form.rows.data, start=form.start.data, sort=form.sort.data)
        qtime = "{:.3f}s".format(float(results.get('responseHeader', {}).get('QTime', 0)) / 1000)
        return render_template('search-results.html', environment=current_app.config['ENVIRONMENT'], base_url=app.config['SERVER_BASE_URL'], auth=session['auth'], form=form, results=results.get('response'), stats=results.get('stats'), error=results.get('error'), qtime=qtime, sort_options=current_app.config['SORT_OPTIONS'])
    return redirect(url_for('index'))

@app.route(app.config['SERVER_BASE_URL']+'classic-form', methods=['GET'], strict_slashes=False)
def classic_form():
    """
    Classic form if no search parameters are sent, otherwise process the parameters
    and redirect to the search results of a built query based on the parameters
    """
    form = ClassicForm(request.args)
    query = []
    if form.astronomy.data:
        query.append("database:astronomy")
    if form.physics.data:
        query.append("database:physics")
    if query:
        query = [" OR ".join(query)]
    if form.refereed.data:
        query.append("property:refereed")
    if form.article.data:
        query.append("property:article")
    if form.author_names.data:
        authors = form.author_names.data.split()
        if form.author_logic.data == "OR":
            query.append("author:({})".format(" OR ".join(["\"{}\"".format(a) for a in authors])))
        elif form.author_logic.data == "AND":
            query.append("author:({})".format(" ".join(["\"{}\"".format(a) for a in authors])))
        else:
            query.append("author:({})".format(" ".join(authors)))
    if form.object_names.data:
        # TODO: form.object_logic.data is not used (not even in BBB)
        objects = form.object_names.data.split()
        results = api.objects_query(objects)
        transformed_objects_query = results.get('query')
        if transformed_objects_query:
            query.append(transformed_objects_query)
    year_from = min(max(form.year_from.data, 0), 9999) if form.year_from.data else 0
    year_to = min(max(form.year_to.data, 0), 9999) if form.year_to.data else 9999
    month_from = min(max(form.month_from.data, 1), 12) if form.month_from.data else 1
    month_to = min(max(form.month_to.data, 1), 12) if form.month_to.data else 12
    pubdate = "pubdate:[{:04}-{:02} TO {:04}-{:02}]".format(year_from, month_from, year_to, month_to)
    if pubdate != "pubdate:[0000-01 TO 9999-12]":
        query.append(pubdate)
    if form.title.data:
        titles = form.title.data.split()
        if form.title_logic.data == "OR":
            query.append(" OR ".join(["title:({})".format(a) for a in titles]))
        elif form.title_logic.data == "AND":
            query.append(" ".join(["title:({})".format(a) for a in titles]))
        else:
            query.append("title:({})".format(" ".join(titles)))
    if form.abstract.data:
        abstracts = form.abstract.data.split()
        if form.abstract_logic.data == "OR":
            query.append(" OR ".join(["abstract:({})".format(a) for a in abstracts]))
        elif form.abstract_logic.data == "AND":
            query.append(" ".join(["abstract:({})".format(a) for a in abstracts]))
        else:
            query.append("abs:({})".format(" ".join(abstracts)))

    if form.bibstem.data:
        bibstems = form.bibstem.data.split(",")
        query.append(" OR ".join(["bibstem:({})".format(b) for b in bibstems]))

    if query:
        return redirect(url_for('search', q=" ".join(query)))
    else:
        return render_template('classic-form.html', environment=current_app.config['ENVIRONMENT'], base_url=app.config['SERVER_BASE_URL'], auth=session['auth'], form=form)

@app.route(app.config['SERVER_BASE_URL']+'paper-form', methods=['GET'], strict_slashes=False)
def paper_form():
    """
    Paper form (left form) if no search parameters are sent, otherwise process the parameters
    and redirect to the search results of a built query based on the parameters
    """
    form = PaperForm(request.args)
    query = []
    if form.bibstem.data:
        query.append("bibstem:({})".format(form.bibstem.data))
    if form.year.data:
        query.append("year:{}".format(form.year.data))
    if form.volume.data:
        query.append("volume:{}".format(form.volume.data))
    if form.page.data:
        query.append("page:{}".format(form.page.data))
    if query:
        return redirect(url_for('search', q=" ".join(query)))
    else:
        return render_template('paper-form.html', environment=current_app.config['ENVIRONMENT'], base_url=app.config['SERVER_BASE_URL'], auth=session['auth'], form=form)

@app.route(app.config['SERVER_BASE_URL']+'paper-form', methods=['POST'], strict_slashes=False)
def paper_form_bibcodes():
    """
    Paper form (right form) if no search parameters are sent, otherwise process the parameters
    and redirect to the search results of a built query based on the parameters
    """
    form = PaperForm()
    if form.bibcodes.data and len(form.bibcodes.data.split()) > 0:
        results = api.store_query(form.bibcodes.data.split()) # Split will get rid of \r\n
        q = "docs({})".format(results['qid'])
        return redirect(url_for('search', q=q))
    return render_template('paper-form.html', environment=current_app.config['ENVIRONMENT'], base_url=app.config['SERVER_BASE_URL'], auth=session['auth'], form=form)


@app.route(app.config['SERVER_BASE_URL']+'abs/<identifier>/<section>', methods=['GET'])
@app.route(app.config['SERVER_BASE_URL']+'abs/<identifier>', methods=['GET'], strict_slashes=False)
def abs(identifier, section=None):
    """
    Show abstract given an identifier
    """
    if section == "exportcitation":
        return _export(identifier)
    elif section == "graphics":
        return _graphics(identifier)
    elif section == "metrics":
        return _metrics(identifier)
    else:
        return _abs(identifier)

def _get_abstract_doc(identifier):
    results = api.abstract(identifier)
    docs = results.get('response', {}).get('docs', [])
    if len(docs) > 0:
        doc = docs[0]
        if not isinstance(doc['title'], list):
            doc['title'] = [doc['title']]
        if 'page' in doc and isinstance(doc['page'], list) and len(doc['page']) > 0:
            doc['page'] = doc['page'][0]
        if doc.get('data'):
            data = []
            for data_element in doc['data']:
                data_components = data_element.split(":")
                if len(data_components) >= 2:
                    try:
                        data.append((data_components[0], int(data_components[1])))
                    except ValueError:
                        data.append((data_components[0], 0))
                else:
                    data.append((data_components[0], 0))
            data = sorted(data, key=functools.cmp_to_key(lambda x, y: 1 if x[1] < y[1] else -1))
            doc['data'] = data
        try:
            doc['pubdate'] = datetime.datetime.strptime(doc['pubdate'], '%Y-%m-00').strftime("%B %Y")
        except ValueError:
            pass
        doc['arXiv'] = None
        for element in doc['identifier']:
            if element.startswith("arXiv:"):
                doc['arXiv'] = element
                break
    else:
        doc = None
        results['error'] = "Record not found."

    associated = api.resolver(doc['bibcode'], resource="associated")
    if 'error' not in associated:
        doc['associated'] = associated.get('links', {}).get('records', [])
    else:
        doc['associated'] = []

    graphics = api.graphics(doc['bibcode'])
    if 'error' not in graphics:
        doc['graphics'] = graphics
    else:
        doc['graphics'] = []

    metrics = api.metrics(doc['bibcode'])
    if 'error' not in metrics:
        doc['metrics'] = metrics
    else:
        doc['metrics'] = []

    return results, doc

def _abs(identifier, section=None):
    results, doc = _get_abstract_doc(identifier)
    return render_template('abstract.html', environment=current_app.config['ENVIRONMENT'], base_url=app.config['SERVER_BASE_URL'], auth=session['auth'], doc=doc, error=results.get('error'))

def _export(identifier):
    """
    Export bibtex given an identifier
    """
    results, doc = _get_abstract_doc(identifier)
    if 'error' not in results and doc:
        doc['export'] = api.export_abstract(doc.get('bibcode')).get('export')
    else:
        doc['export'] = None
    return render_template('abstract-export.html', environment=current_app.config['ENVIRONMENT'], base_url=app.config['SERVER_BASE_URL'], auth=session['auth'], doc=doc, error=results.get('error'))

def _graphics(identifier):
    """
    Graphics for a given identifier
    """
    results, doc = _get_abstract_doc(identifier)
    if len(doc.get('graphics', {}).get('figures', [])) > 0:
        return render_template('abstract-graphics.html', environment=current_app.config['ENVIRONMENT'], base_url=app.config['SERVER_BASE_URL'], auth=session['auth'], doc=doc, error=results.get('error'))
    else:
        abort(404)

def _metrics(identifier):
    """
    Metrics for a given identifier
    """
    results, doc = _get_abstract_doc(identifier)
    if int(doc.get('metrics', {}).get('citation stats', {}).get('total number of citations', 0)) > 0 or int(doc.get('metrics', {}).get('basic stats', {}).get('total number of reads', 0)) > 0:
        return render_template('abstract-metrics.html', environment=current_app.config['ENVIRONMENT'], base_url=app.config['SERVER_BASE_URL'], auth=session['auth'], doc=doc, error=results.get('error'))
    else:
        abort(404)

@app.route(app.config['SERVER_BASE_URL']+'core/always', methods=['GET'], strict_slashes=False)
@app.route(app.config['SERVER_BASE_URL']+'core/always/<path:url>', methods=['GET'])
def core_always(url=None):
    target_url = _build_target_url(request, url)
    r = redirect(target_url)
    r.set_cookie('core', 'always')
    return r

@app.route(app.config['SERVER_BASE_URL']+'core/never', methods=['GET'], strict_slashes=False)
@app.route(app.config['SERVER_BASE_URL']+'core/never/<path:url>', methods=['GET'])
def core_never(url=None):
    target_url = _build_target_url(request, url)
    r = redirect(target_url)
    r.set_cookie('core', 'never') # Keep cookie instead of deleting with r.delete_cookie('core')
    return r

def _build_target_url(request, url):
    full_url = request.url_root
    params_dict = {}
    for accepted_param in ('q', 'rows', 'start', 'sort'):
        if accepted_param in request.args:
            params_dict[accepted_param] = request.args.get(accepted_param)
    params = urllib.parse.urlencode(params_dict)
    if url:
        full_url += url
    if params:
        if full_url[-1] != "/":
            full_url += "/"
        full_url += params
    return full_url
