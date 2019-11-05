import time
import urllib.parse
from flask import render_template, session, request, redirect, g, current_app, url_for, abort
from adscore.app import app, limiter, redis_client, get_remote_address
from adscore import api
from adscore import crawlers
from adscore.forms import ModernForm, PaperForm, ClassicForm
from adscore.tools import is_expired

@limiter.request_filter
def probes():
    """
    If the request is related to the readiness/liveness probe, do not rate limit.
    """
    return request.path in ('/ready', '/alive')

@limiter.request_filter
def header_whitelist():
    """
    If the request has an access token stored in the session, it means that the
    request sent a session cookie in the headers stored as requested by a previous
    request that was answered by ADS Core. The client is well behaving, storing
    cookies set by ADS Core and thus, we do not want to rate limit them.

    Rate limits are only to protect us from bootstrapping thousands of access
    tokens in the database.
    """
    if 'auth' in session:
        return True
    else:
        user_agent = request.headers.get('User-Agent')
        remote_ip = get_remote_address()
        #### For testing purposes:
        #user_agent = "Googlebot"
        #remote_ip = "66.249.66.1" # crawl-66-249-66-1.googlebot.com.
        #user_agent = "DuckDuckBot"
        #remote_ip = "50.16.241.117"
        #remote_ip = "127.0.0.1"
        evaluation = crawlers.evaluate(remote_ip, user_agent)

        if evaluation in (crawlers.VERIFIED_BOT, crawlers.UNVERIFIABLE_BOT, crawlers.POTENTIAL_MALICIOUS_BOT):
            return True
    return False

@app.before_request
def before_request():
    """
    Store API anonymous cookie in session or if it exists, check if it has expired
    """
    if request.path in ('/ready', '/alive'):
        # Do not bootstrap readiness/liveness probes
        return
    g.request_start_time = time.time()
    g.request_time = lambda: "{:.3f}s".format((time.time() - g.request_start_time))
    if 'cookies' not in session:
        session['cookies'] = {}
    if request.cookies.get('session'):
        # Re-use BBB session, if it is valid, the same BBB token will be returned by bootstrap
        # thus if the user was authenticated, it will use the user token
        session['cookies']['session'] = request.cookies.get('session')
    if 'auth' not in session or is_expired(session['auth']):
        user_agent = request.headers.get('User-Agent')
        remote_ip = get_remote_address()
        #### For testing purposes:
        #user_agent = "Googlebot"
        #remote_ip = "66.249.66.1" # crawl-66-249-66-1.googlebot.com.
        #user_agent = "DuckDuckBot"
        #remote_ip = "50.16.241.117"
        #remote_ip = "127.0.0.1"
        evaluation = crawlers.evaluate(remote_ip, user_agent)
        if evaluation == crawlers.VERIFIED_BOT:
            # Extremely high rate limit
            session['auth'] = { 'access_token': app.config['VERIFIED_BOTS_ACCESS_TOKEN'], 'expire_in': "2050-01-01T00:00:00", 'bot': True }
        elif evaluation == crawlers.UNVERIFIABLE_BOT:
            # Slightly higher rate limit
            session['auth'] = { 'access_token': app.config['UNVERIFIABLE_BOTS_ACCESS_TOKEN'], 'expire_in': "2050-01-01T00:00:00", 'bot': True }
        elif evaluation == crawlers.POTENTIAL_MALICIOUS_BOT:
            # Rate limits as a regular user with the advantage that there is no bootstrap
            session['auth'] = { 'access_token': app.config['MALICIOUS_BOTS_ACCESS_TOKEN'], 'expire_in': "2050-01-01T00:00:00", 'bot': True }
        else:
            session['auth'] = api.bootstrap()

@app.errorhandler(429)
def ratelimit_handler(e):
    user_agent = request.headers.get('User-Agent')
    remote_ip = get_remote_address()
    evaluation = crawlers.evaluate(remote_ip, user_agent)
    if evaluation == crawlers.VERIFIED_BOT:
        app.logger.info("Rate limited a request classified as 'VERIFIED_BOT'")
    elif evaluation == crawlers.UNVERIFIABLE_BOT:
        app.logger.info("Rate limited a request classified as 'UNVERIFIABLE_BOT'")
    elif evaluation == crawlers.POTENTIAL_MALICIOUS_BOT:
        app.logger.info("Rate limited a request classified as 'POTENTIAL_MALICIOUS_BOT'")
    elif evaluation == crawlers.POTENTIAL_USER:
        app.logger.info("Rate limited a request classified as 'POTENTIAL_USER'")
    else:
        # None
        app.logger.info("Rate limited a request not classified: '%s' - '%s'", remote_ip, user_agent)
    form = ModernForm()
    return render_template('429.html', environment=current_app.config['ENVIRONMENT'], base_url=app.config['SERVER_BASE_URL'], request_path=request.path[1:], form=form, code=429), 429

@app.errorhandler(404)
def page_not_found(e):
    form = ModernForm()
    return render_template('404.html', environment=current_app.config['ENVIRONMENT'], base_url=app.config['SERVER_BASE_URL'], request_path=request.path[1:], form=form, code=404), 404

@app.errorhandler(500)
def internal_error(e):
    form = ModernForm()
    return render_template('500.html', environment=current_app.config['ENVIRONMENT'], base_url=app.config['SERVER_BASE_URL'], request_path=request.path[1:], form=form, code=500), 500


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
    form = ModernForm.parse(params or request.args)
    if form.p_.data > 0:
        # Redirect to correct the start parameter to match the requested page
        computed_start = (form.p_.data - 1) * form.rows.data
        if form.start.data != computed_start:
            return redirect(url_for('search', q=form.q.data, sort=form.sort.data, rows=form.rows.data, start=computed_start))
    elif form.q.data and len(form.q.data) > 0:
        if not form.sort.raw_data:
            # There was not previous sorting specified
            if "similar(" in form.q.data or "trending(" in form.q.data:
                form.sort.data = "score desc"
            elif "references(" in form.q.data:
                form.sort.data = "first_author asc"
        results = api.Search(form.q.data, rows=form.rows.data, start=form.start.data, sort=form.sort.data)
        qtime = "{:.3f}s".format(float(results.get('responseHeader', {}).get('QTime', 0)) / 1000)
        return render_template('search-results.html', environment=current_app.config['ENVIRONMENT'], base_url=app.config['SERVER_BASE_URL'], auth=session['auth'], form=form, results=results.get('response'), stats=results.get('stats'), error=results.get('error'), qtime=qtime, sort_options=current_app.config['SORT_OPTIONS'])
    else:
        return redirect(url_for('index'))

@app.route(app.config['SERVER_BASE_URL']+'classic-form', methods=['GET'], strict_slashes=False)
def classic_form():
    """
    Classic form if no search parameters are sent, otherwise process the parameters
    and redirect to the search results of a built query based on the parameters
    """
    form = ClassicForm(request.args)
    query = form.build_query()
    if query:
        return redirect(url_for('search', q=query))
    else:
        return render_template('classic-form.html', environment=current_app.config['ENVIRONMENT'], base_url=app.config['SERVER_BASE_URL'], auth=session['auth'], form=form, sort_options=current_app.config['SORT_OPTIONS'])

@app.route(app.config['SERVER_BASE_URL']+'paper-form', methods=['GET', 'POST'], strict_slashes=False)
def paper_form():
    """
    Paper form x if no search parameters are sent, otherwise process the parameters
    and redirect to the search results of a built query based on the parameters
    """
    if request.method == 'POST':
        # Right form with bibcode list
        form = PaperForm(request.form)
    else: # GET
        # Left form with fields
        form = PaperForm(request.args)
    query = form.build_query()
    if query:
        return redirect(url_for('search', q=query))
    else:
        return render_template('paper-form.html', environment=current_app.config['ENVIRONMENT'], base_url=app.config['SERVER_BASE_URL'], auth=session['auth'], form=form)

@app.route(app.config['SERVER_BASE_URL']+'public-libraries/<identifier>', methods=['GET'], strict_slashes=False)
def public_libraries(identifier):
    """
    Display public library
    """
    #return redirect(url_for('search', q=f"docs(library/{identifier})"))
    return search(params=f"q=docs(library/{identifier})")

@app.route(app.config['SERVER_BASE_URL']+'abs/<path:alt_identifier>', methods=['GET'])
@app.route(app.config['SERVER_BASE_URL']+'abs/<identifier>/<section>', methods=['GET'])
@app.route(app.config['SERVER_BASE_URL']+'abs/<identifier>', methods=['GET'], strict_slashes=False)
def abs(identifier=None, section=None, alt_identifier=None):
    """
    Show abstract given an identifier
    """
    if identifier:
        if section in (None, "abstract"):
            return _abstract(identifier)
        elif section == "citations":
            return _operation("citations", identifier)
        elif section == "references":
            return _operation("references", identifier)
        elif section == "coreads":
            return _operation("trending", identifier)
        elif section == "similar":
            return _operation("similar", identifier)
        elif section == "toc":
            return _toc(identifier)
        elif section == "exportcitation":
            return _export(identifier)
        elif section == "graphics":
            return _graphics(identifier)
        elif section == "metrics":
            return _metrics(identifier)
        else:
            # An alternative identifier mistaken by a composition of id + section
            return _abstract(identifier+'/'+section)
    elif alt_identifier:
        # Alternative identifiers such as DOIs (e.g., /abs/10.1051/0004-6361/201423945)
        return _abstract(alt_identifier)
    else:
        abort(404)

def _cached_render_template(key, *args, **kwargs):
    """
    Cache only the template rendering so that other parts of the code get executed
    such as connecting to link_gateway to register clicks
    """
    try:
        rendered_template = redis_client.get(key)
        if rendered_template:
            rendered_template = rendered_template.decode('utf-8')
    except Exception:
        # Do not affect users if connection to Redis is lost in production
        if app.debug:
            raise
        rendered_template = None

    if not rendered_template:
        rendered_template = render_template(*args, **kwargs)

    try:
        redis_client.set(key, rendered_template, ex=app.config['REDIS_EXPIRATION_TIME'])
    except Exception:
        # Do not affect users if connection to Redis is lost in production
        if app.debug:
            raise
    return rendered_template

def _abstract(identifier, section=None):
    doc = api.Abstract(identifier)
    if 'bibcode' in doc:
        if doc['bibcode'] != identifier:
            if current_app.config['ENVIRONMENT'] == "localhost":
                target_url = url_for('abs', identifier=doc['bibcode'], section='abstract', _external=True, _scheme='https')
            else:
                target_url = url_for('abs', identifier=doc['bibcode'], section='abstract')
            return redirect(target_url, code=301)
        api.link_gateway(doc['bibcode'], "abstract")
        key = "/".join((app.config['REDIS_RENDER_KEY_PREFIX'], identifier, 'abstract'))
        return _cached_render_template(key, 'abstract.html', environment=current_app.config['ENVIRONMENT'], base_url=app.config['SERVER_BASE_URL'], auth=session['auth'], doc=doc)
    else:
        abort(404)

def _operation(operation, identifier):
    doc = api.Abstract(identifier)
    if 'bibcode' in doc:
        api.link_gateway(doc['bibcode'], operation)
        if operation in ("trending", "similar"):
            sort = "score desc"
        elif operation == "references":
            sort = "first_author asc"
        else:
            sort = "date desc"
        target_url = url_for('search', q=f'{operation}(bibcode:{doc["bibcode"]})', sort=sort)
        if request.cookies.get('core', 'never') == 'always':
            return redirect(target_url)
        else:
            key = "/".join((app.config['REDIS_RENDER_KEY_PREFIX'], identifier, operation))
            return _cached_render_template(key, 'abstract-empty.html', environment=current_app.config['ENVIRONMENT'], base_url=app.config['SERVER_BASE_URL'], auth=session['auth'], doc=doc)
    else:
        abort(404)

def _toc(identifier):
    doc = api.Abstract(identifier)
    if 'bibcode' in doc:
        api.link_gateway(doc['bibcode'], "toc")
        target_url = url_for('search', q=f'bibcode:{doc["bibcode"][:13]}*')
        if request.cookies.get('core', 'never') == 'always':
            return redirect(target_url)
        else:
            key = "/".join((app.config['REDIS_RENDER_KEY_PREFIX'], identifier, 'toc'))
            return _cached_render_template(key, 'abstract-empty.html', environment=current_app.config['ENVIRONMENT'], base_url=app.config['SERVER_BASE_URL'], auth=session['auth'], doc=doc)
    else:
        abort(404)

def _export(identifier):
    """
    Export bibtex given an identifier
    """
    doc = api.Abstract(identifier)
    if doc.get('export'):
        if 'bibcode' in doc:
            api.link_gateway(doc['bibcode'], "exportcitation")
        key = "/".join((app.config['REDIS_RENDER_KEY_PREFIX'], identifier, 'export'))
        return _cached_render_template(key, 'abstract-export.html', environment=current_app.config['ENVIRONMENT'], base_url=app.config['SERVER_BASE_URL'], auth=session['auth'], doc=doc)
    else:
        abort(404)

def _graphics(identifier):
    """
    Graphics for a given identifier
    """
    doc = api.Abstract(identifier)
    if len(doc.get('graphics', {}).get('figures', [])) > 0:
        if 'bibcode' in doc:
            api.link_gateway(doc['bibcode'], "graphics")
        key = "/".join((app.config['REDIS_RENDER_KEY_PREFIX'], identifier, 'graphics'))
        return _cached_render_template(key, 'abstract-graphics.html', environment=current_app.config['ENVIRONMENT'], base_url=app.config['SERVER_BASE_URL'], auth=session['auth'], doc=doc)
    else:
        abort(404)

def _metrics(identifier):
    """
    Metrics for a given identifier
    """
    doc = api.Abstract(identifier)
    if int(doc.get('metrics', {}).get('citation stats', {}).get('total number of citations', 0)) > 0 or int(doc.get('metrics', {}).get('basic stats', {}).get('total number of reads', 0)) > 0:
        if 'bibcode' in doc:
            api.link_gateway(doc['bibcode'], "metrics")
        key = "/".join((app.config['REDIS_RENDER_KEY_PREFIX'], identifier, 'metrics'))
        return _cached_render_template(key, 'abstract-metrics.html', environment=current_app.config['ENVIRONMENT'], base_url=app.config['SERVER_BASE_URL'], auth=session['auth'], doc=doc)
    else:
        abort(404)

@app.route(app.config['SERVER_BASE_URL']+'core/always', methods=['GET'], strict_slashes=False)
@app.route(app.config['SERVER_BASE_URL']+'core/always/<path:url>', methods=['GET'])
def core_always(url=None):
    target_url = request.url_root + _build_full_ads_url(request, url)
    r = redirect(target_url)
    r.set_cookie('core', 'always')
    return r

@app.route(app.config['SERVER_BASE_URL']+'core/never', methods=['GET'], strict_slashes=False)
@app.route(app.config['SERVER_BASE_URL']+'core/never/<path:url>', methods=['GET'])
def core_never(url=None):
    target_url = request.url_root + _build_full_ads_url(request, url)
    r = redirect(target_url)
    r.set_cookie('core', 'never') # Keep cookie instead of deleting with r.delete_cookie('core')
    return r

@app.route(app.config['SERVER_BASE_URL']+'core/<path:url>', methods=['GET'])
@app.route(app.config['SERVER_BASE_URL']+'core/', methods=['GET'], strict_slashes=False)
def core(url=None):
    target_url = _build_full_ads_url(request, url)
    return render_template('switch.html', environment=current_app.config['ENVIRONMENT'], base_url=app.config['SERVER_BASE_URL'], auth=session['auth'], request_path=request.path[1:], target_url=target_url)

def _build_full_ads_url(request, url):
    """
    Build full ADS url from a core request
    """
    full_url = ""
    params_dict = {}
    for accepted_param in ('q', 'rows', 'start', 'sort', 'p_'):
        if accepted_param in request.args:
            params_dict[accepted_param] = request.args.get(accepted_param)
    params = urllib.parse.urlencode(params_dict)
    if url:
        full_url += url
    if params:
        if len(full_url) >=1 and full_url[-1] != "/":
            full_url += "/"
        full_url += params
    return full_url
