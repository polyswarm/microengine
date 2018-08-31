import importlib

from microengine.clamav import ClamavMicroengine
from microengine.eicar import EicarMicroengine
from microengine.multi import MultiMicroengine
from microengine.scratch import ScratchMicroengine
from microengine.yara import YaraMicroengine


def choose_backend(backend):
    """Resolves microengine name string to implementation

    Args:
        backend (str): Name of the backend to load, either one of the predefined
            implementations or the name of a module to load (module:ClassName syntax or default of module:Microengine)
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
    elif backend == 'yara':
        micro_engine_class = YaraMicroengine
    elif backend == 'multi':
        micro_engine_class = MultiMicroengine
    else:
        import_l = backend.split(":")
        micro_engine_module_s = import_l[0]

        micro_engine_module = importlib.import_module(micro_engine_module_s)
        micro_engine_class = micro_engine_module.Microengine if ":" not in backend else eval(
            "micro_engine_module.{0}".format(import_l[1]))

    if micro_engine_class is None:
        raise Exception("No microengine backend found {0}".format(backend))

    return micro_engine_class
