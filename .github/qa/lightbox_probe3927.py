"""Observe exact27 lightbox tests without changing source, gestures or timeouts."""
import argparse
from collections import Counter, deque
import functools
import json
import os
from pathlib import Path
import platform
import sys
import time
import traceback
import unittest


def enum_value(value):
    return getattr(value,'value',value)


def point(value):
    return None if value is None else [round(value.x(),4),round(value.y(),4)]


def rectangle(value):
    return [round(value.x(),4),round(value.y(),4),round(value.width(),4),round(value.height(),4)]


class Recorder:
    def __init__(self):
        self.active=False;self.viewer=None;self.wait_frame=None;self.test=None
        self.events=deque(maxlen=1600);self.counts=Counter();self.tests=[];self.failures=[]
        self.run='';self.variant='baseline';self.started=time.monotonic();self.test_started=self.started

    def frame_state(self,frame):
        from shiboken6 import isValid
        if frame is None:return None
        result={'id':id(frame),'valid':isValid(frame)}
        if not result['valid']:return result
        try:
            result.update(visible=bool(frame.frame_visible),opacity=round(frame.opacity(),5),
                rect=rectangle(frame.rect),in_scene=frame.scene() is not None,
                fade_state=enum_value(frame.fade.state()),fade_time=frame.fade.currentTime(),
                fade_duration=frame.fade.duration(),fade_start=frame.fade.startValue(),fade_end=frame.fade.endValue())
        except (RuntimeError,AttributeError):result['partially_constructed']=True
        return result

    def _snapshot(self):
        from shiboken6 import isValid
        viewer=self.viewer
        if viewer is None or not isValid(viewer):return {'viewer':None}
        result={'viewer':id(viewer)}
        try:
            view=viewer.view;viewport=view.viewport();transform=view.transform();images=viewer.images
            result.update(view=id(view),viewport_geometry=rectangle(viewport.geometry()),
                viewport_rect=rectangle(viewport.rect()),view_geometry=rectangle(view.geometry()),
                viewer_geometry=rectangle(viewer.geometry()),owner_geometry=rectangle(viewer.owner.geometry()),
                dpr=[viewer.devicePixelRatioF(),view.devicePixelRatioF(),viewport.devicePixelRatioF()],
                transform=[round(transform.m11(),6),round(transform.m22(),6),round(transform.dx(),6),round(transform.dy(),6)],
                photo_rect=rectangle(view.photo_rect),pointer=point(viewer.face_pointer),
                pointer_scene=point(view.mapToScene(viewer.face_pointer)) if viewer.face_pointer is not None else None,
                controls_visible=bool(viewer.controls_visible),all_faces=viewer.all_faces.isChecked(),
                selecting_face=view.selecting_face,fit_pending=view._fit_timer.isActive(),
                fit_context=view._fit_context,fit_requested=view._fit_requested_context,
                render_pending=viewer.render_timer.isActive(),images_idle=bool(images.idle),
                images_active=images.active is not None,images_pending=images.pending is not None,
                images_generation=images.generation,images_sequence=images.sequence,
                original_present=viewer.original_image is not None,image_item_present=viewer.image_item is not None,
                manual_zoom=view.manual_zoom,fit_scale=round(view.fit_scale,6),
                frames=[self.frame_state(frame) for frame in viewer.face_items],
                face_centers=[point(view.mapFromScene(frame.rect.center())) for frame in viewer.face_items])
            if self.wait_frame is not None:result['wait_frame']=self.frame_state(self.wait_frame)
        except (RuntimeError,AttributeError,TypeError):result['partially_constructed']=True
        return result

    def snapshot(self):
        try:return self._snapshot()
        except Exception as error:return {'observer_snapshot_error':type(error).__name__}

    def record(self,event,**details):
        if not self.active:return
        self.counts[event]+=1
        state=self.snapshot()
        if event=='test_hover.after' and self.first_hover is None:self.first_hover=state
        if self.first_hover is not None and event not in ('test_hover.before','test_hover.after'):
            self.after_hover_counts[event]+=1
        self.events.append({'ms':round((time.monotonic()-self.test_started)*1000,3),
                            'event':event,**details,'state':state})

    def start(self,test):
        self.test=test.id();self.active=test.__class__.__module__=='test_photo_lightbox'
        self.viewer=None;self.wait_frame=None;self.events.clear();self.counts.clear()
        self.first_hover=None;self.after_hover_counts=Counter()
        self.test_started=time.monotonic();self.failed=False

    def failed_test(self,test,error,kind):
        self.failed=True
        captured=sum(value['variant']==self.variant for value in self.failures)
        if self.active and captured<3:
            self.record('assertion_failure',kind=kind)
            self.failures.append({'run':self.run,'variant':self.variant,'test':test.id(),'kind':kind,
                'traceback':''.join(traceback.format_exception(*error))[-8000:],
                'failure_state':self.snapshot(),'event_counts':dict(self.counts),
                'events':list(self.events)[-200:]})

    def stop(self,test):
        self.tests.append({'run':self.run,'variant':self.variant,'test':test.id(),'failed':self.failed,
            'seconds':round(time.monotonic()-self.test_started,4),
            'event_counts':dict(self.counts) if self.active else {},
            'first_hover_state':self.first_hover if self.active else None,
            'events_after_first_hover':dict(self.after_hover_counts) if self.active else {}})
        self.active=False;self.viewer=None;self.wait_frame=None


REC=Recorder()


def install_observers():
    from PySide6.QtCore import QEvent
    from photo_lightbox import FaceOutline,OriginalCanvas,PhotoLightbox
    import test_photo_lightbox

    def observed(cls,name,details=lambda *_a,**_k:{}):
        original=getattr(cls,name)
        @functools.wraps(original)
        def wrapped(self,*args,**kwargs):
            context=details(self,*args,**kwargs)
            REC.record(cls.__name__+'.'+name+'.before',**context)
            try:return original(self,*args,**kwargs)
            finally:REC.record(cls.__name__+'.'+name+'.after',**context)
        setattr(cls,name,wrapped)

    init=PhotoLightbox.__init__
    @functools.wraps(init)
    def start_viewer(self,*args,**kwargs):
        if REC.active:REC.viewer=self
        result=init(self,*args,**kwargs)
        REC.record('viewer_initialized')
        return result
    PhotoLightbox.__init__=start_viewer

    for name in ('resizeEvent','defer_fit','fit_if_automatic','fit_photo','invalidate_fit'):
        observed(OriginalCanvas,name)
    observed(PhotoLightbox,'set_face_pointer',lambda _self,value:{'supplied_pointer':point(value)})
    observed(PhotoLightbox,'zoom_changed',lambda _self,value:{'supplied_zoom':value})
    for name in ('refresh_faces','update_face_visibility','show_controls','hide_controls','resizeEvent','fit'):
        observed(PhotoLightbox,name)
    observed(PhotoLightbox,'image_received',lambda _self,result,error:{
        'received_scale':result.get('scale') if result else None,'received_error':bool(error)})
    observed(FaceOutline,'show_frame',lambda self,visible:{'subject':id(self),'requested_visible':bool(visible),
        'subject_frame':REC.frame_state(self)})

    viewport_event=OriginalCanvas.viewportEvent
    tracked={QEvent.Type.Leave,QEvent.Type.Enter,QEvent.Type.Resize,QEvent.Type.Show,QEvent.Type.Hide,
             QEvent.Type.LayoutRequest,QEvent.Type.MouseMove,QEvent.Type.FocusIn,QEvent.Type.FocusOut,
             QEvent.Type.WindowActivate,QEvent.Type.WindowDeactivate}
    @functools.wraps(viewport_event)
    def observe_viewport(self,event):
        capture=event.type() in tracked
        details={'qt_event':event.type().name}
        if hasattr(event,'position'):details['event_position']=point(event.position())
        if capture:REC.record('viewport_event.before',**details)
        try:return viewport_event(self,event)
        finally:
            if capture:REC.record('viewport_event.after',**details)
    OriginalCanvas.viewportEvent=observe_viewport
    event_filter=PhotoLightbox.eventFilter
    @functools.wraps(event_filter)
    def observe_filter(self,watched,event):
        capture=event.type() in tracked
        details={'qt_event':event.type().name,'watched':'owner' if watched is self.owner else 'overlay'}
        if capture:REC.record('viewer_event_filter.before',**details)
        try:return event_filter(self,watched,event)
        finally:
            if capture:REC.record('viewer_event_filter.after',**details)
    PhotoLightbox.eventFilter=observe_filter

    hover=test_photo_lightbox.LightboxContextTests.hover
    @functools.wraps(hover)
    def observe_hover(self,position):
        REC.record('test_hover.before',supplied_pointer=point(position))
        try:return hover(self,position)
        finally:REC.record('test_hover.after',supplied_pointer=point(position))
    test_photo_lightbox.LightboxContextTests.hover=observe_hover

    wait=test_photo_lightbox.LightboxContextTests.wait_for_fade
    @functools.wraps(wait)
    def observe_wait(self,frame,visible):
        REC.wait_frame=frame;REC.record('wait_for_fade.begin',expected_visible=visible)
        try:return wait(self,frame,visible)
        finally:REC.record('wait_for_fade.end',expected_visible=visible)
    test_photo_lightbox.LightboxContextTests.wait_for_fade=observe_wait


class Result(unittest.TextTestResult):
    def startTest(self,test):REC.start(test);super().startTest(test)
    def stopTest(self,test):REC.stop(test);super().stopTest(test)
    def addFailure(self,test,error):REC.failed_test(test,error,'failure');super().addFailure(test,error)
    def addError(self,test,error):REC.failed_test(test,error,'error');super().addError(test,error)


def settled_image(self):
    """Observe a test-only readiness variant within the original 3-second bound."""
    from PySide6.QtCore import QEvent
    from PySide6.QtTest import QTest
    viewer=self.viewer;view=viewer.view
    deadline=time.monotonic()+3;previous=None;stable=0
    REC.record('candidate_settled_wait.begin')
    while time.monotonic()<deadline:
        viewer.layout().activate()
        self.app.sendPostedEvents(None,QEvent.Type.LayoutRequest)
        self.app.processEvents()
        transform=view.viewportTransform()
        signature=(viewer.geometry().getRect(),view.geometry().getRect(),view.viewport().geometry().getRect(),
                   viewer.devicePixelRatioF(),view.devicePixelRatioF(),
                   transform.m11(),transform.m22(),transform.dx(),transform.dy())
        ready=(viewer.original_image is not None and viewer.image_item is not None and viewer.images.idle
               and not view._fit_timer.isActive() and not viewer.render_timer.isActive())
        stable=stable+1 if ready and signature==previous else 0
        if stable>=2:
            REC.record('candidate_settled_wait.ready');return
        previous=signature
        QTest.qWait(1)
    REC.record('candidate_settled_wait.timeout')
    self.fail('Viewer source/render/layout/fit did not settle')


def execute(suite,label):
    REC.run=label
    result=unittest.TextTestRunner(verbosity=1,resultclass=Result).run(suite)
    return {'run':label,'tests':result.testsRun,'failures':len(result.failures),'errors':len(result.errors),
            'skipped':len(result.skipped),'success':result.wasSuccessful()}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--backend',choices=('offscreen','cocoa'),required=True)
    parser.add_argument('--prelude-discover',action='store_true')
    parser.add_argument('--output',type=Path,required=True)
    args=parser.parse_args()
    if os.environ.get('QT_QPA_PLATFORM')!=args.backend:raise RuntimeError('Diagnostic backend differs from request.')
    if args.output.exists():raise FileExistsError('Preserve the diagnostic report.')
    source=Path.cwd().resolve(strict=True)
    if not (source/'test_photo_lightbox.py').is_file():raise RuntimeError('Use the exact extracted source as working directory.')
    sys.path.insert(0,str(source))
    from PySide6 import __version__ as pyside_version
    from PySide6.QtCore import qVersion
    from PySide6.QtWidgets import QApplication
    install_observers()
    runs=[]
    if args.prelude_discover:
        if args.backend!='offscreen':raise RuntimeError('The original discovery prelude is offscreen only.')
        runs.append(execute(unittest.TestLoader().discover('.',pattern='test_photo*.py'),'original-photo-discovery'))
    for repeat in range(10):
        runs.append(execute(unittest.TestLoader().loadTestsFromName('test_photo_lightbox'),f'focused-{repeat+1}'))
    # Preserve the original lazy QApplication creation order during baseline.
    # The original test classes create it in setUpClass when first needed.
    app=QApplication.instance() or QApplication([])
    if app.platformName()!=args.backend:raise RuntimeError('The actual Qt platform differs from the requested backend.')
    import test_photo_lightbox
    original_wait=test_photo_lightbox.LightboxContextTests.wait_for_image
    test_photo_lightbox.LightboxContextTests.wait_for_image=settled_image
    REC.variant='settled-fixture'
    try:
        for repeat in range(10):
            runs.append(execute(unittest.TestLoader().loadTestsFromName('test_photo_lightbox'),f'settled-focused-{repeat+1}'))
    finally:test_photo_lightbox.LightboxContextTests.wait_for_image=original_wait
    report={'schema':1,'ok':True,'diagnostic_id':'lightbox-diag3927','requested_backend':args.backend,
        'actual_backend':app.platformName(),'host':platform.platform(),'machine':platform.machine(),
        'python':platform.python_version(),'pyside':pyside_version,'qt':qVersion(),
        'default_font':app.font().family(),
        'screens':[{'dpr':screen.devicePixelRatio(),'geometry':rectangle(screen.geometry()),
                    'available_geometry':rectangle(screen.availableGeometry()),'dpi':screen.logicalDotsPerInch()}
                   for screen in app.screens()],
        'repeats_per_variant':10,'variants':['baseline','settled-fixture'],
        'original_discovery_included':args.prelude_discover,'runs':runs,
        'tests':REC.tests,'captured_failures':REC.failures,
        'production_source_modified':False,'timeouts_modified':False,'fade_assertions_modified':False,
        'settled_fixture_only_monkeypatch':True,'wait_bound_seconds':3,
        'cursor_position_controlled':False,'actual_user_models_or_originals_loaded':False}
    encoded=json.dumps(report,ensure_ascii=False,separators=(',',':')).encode('utf8')
    while len(encoded)>900000 and any(len(value['events'])>12 for value in report['captured_failures']):
        for value in report['captured_failures']:value['events']=value['events'][len(value['events'])//2:]
        encoded=json.dumps(report,ensure_ascii=False,separators=(',',':')).encode('utf8')
    if len(encoded)>900000:raise RuntimeError('Bounded diagnostic exceeded its output limit.')
    with args.output.open('xb') as output:output.write(encoded)
    print('LIGHTBOX_DIAGNOSTIC_JSON '+encoded.decode('utf8'),flush=True)
    # Assertion failures are evidence: the diagnostic job still completes and
    # encrypts its reports. Setup/probe failures use a nonzero process exit.
    return 0


if __name__=='__main__':raise SystemExit(main())
