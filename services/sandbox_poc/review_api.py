"""UI for a supplied upstream handoff; never connects to its source database."""
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse, JSONResponse
from starlette.middleware.trustedhost import TrustedHostMiddleware

from .router import router
from .service import SandboxService


def create_app(handoff):
    engine = SandboxService("").validate_handoff(handoff)
    handoff = handoff.model_copy(update={"assessment": engine.bind_assessment(handoff.snapshot, handoff.assessment)})
    app = FastAPI(title="DBGuardAI upstream handoff review")
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=['127.0.0.1', 'localhost', 'testserver'])

    @app.middleware('http')
    async def same_origin(request, call_next):
        origin = request.headers.get('origin')
        if request.method not in ('GET', 'HEAD', 'OPTIONS') and origin and origin != str(request.base_url).rstrip('/'):
            return JSONResponse({'detail':'Cross-origin requests are not allowed'}, status_code=403)
        response = await call_next(request)
        response.headers['Cache-Control'] = 'no-store'
        response.headers['X-Content-Type-Options'] = 'nosniff'
        return response

    app.include_router(router)

    @app.get('/', include_in_schema=False)
    def index():
        return FileResponse(Path(__file__).parent/'ui/index.html')

    @app.get('/review/context')
    def context():
        return {'mode':'upstream-handoff', 'fixture_approval':False, 'handoff':handoff.model_dump()}

    return app
