import importlib

from microengine.clamav import ClamavMicroengine
from microengine.eicar import EicarMicroengine
from microengine.scratch import ScratchMicroengine


def choose_backend(backend):
    """Resolves microengine name string to implementation

    Args:
        backend (str): Name of the backend to load, either one of the predefined
            implementations or the name of a module to load
    Returns:
        (Class): Microengine class of the selected implementation
    Raises:
        (Exception): If backend is not found
    """
    micro_engine_class = None
    if backend == 'scratch':
        # ScratchMicroengine(polyswarmd_addr, keyfile, password).run(testing)
        micro_engine_class = ScratchMicroengine
    elif backend == 'eicar':
        micro_engine_class = EicarMicroengine  # EicarMicroengine(polyswarmd_addr, keyfile, password).run(testing)
    elif backend == 'clamav':
        micro_engine_class = ClamavMicroengine  # ClamavMicroengine(polyswarmd_addr, keyfile, password).run(testing)
    else:
        micro_engine_module = importlib.import_module(backend)
        micro_engine_class = micro_engine_module.Microengine
        # todo make the class name customizable

    if micro_engine_class is None:
        raise Exception("No microengine backend found {0}".format(backend))

    return micro_engine_class
