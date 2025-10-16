import sys
import logging
import subprocess
import time
import platform
from abc import ABC, abstractmethod

from basellm_provider import BaseLLMProvider

logger = logging.getLogger(__name__)


class OllamaProvider(BaseLLMProvider):
    def __init__(self, model_name: str = "llama3.2", auto_start: bool = True):
        self.model_name = model_name
        self.auto_start = auto_start
        self.ollama_process = None
        self._ollama_module = None
        self._initialize_ollama()

    def _initialize_ollama(self):
        try:
            import ollama

            self._ollama_module = ollama
            logger.info("Ollama imported successfully!")
        except ImportError:
            logger.error("Ollama not installed. Run: pip install ollama")
            sys.exit(1)

        if self.auto_start:
            self._ensure_ollama_running()

        self._ensure_model_available()

    def _is_ollama_running(self) -> bool:
        try:
            self._ollama_module.list()
            return True
        except Exception:
            return False

    def _start_ollama_service(self) -> bool:
        """this function handles the start of the Ollama service on Windows and Unix systems"""

        system = platform.system().lower()
        logger.info("Attempting to start Ollama...")

        try:
            if system == "windows":
                subprocess.Popen(
                    ["ollama", "serve"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    creationflags=(
                        subprocess.CREATE_NEW_PROCESS_GROUP
                        if system == "windows"
                        else 0
                    ),
                )
            else:
                # only considering UNIX systems here
                self.ollama_process = subprocess.Popen(
                    ["ollama", "serve"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    start_new_session=True,
                )

            for i in range(10):
                time.sleep(1)
                if self._is_ollama_running():
                    logger.info("Ollama service started successfully")
                    return True
                logger.debug(f"Waiting for Ollama to start... ({i+1}/10)")

            logger.warning("Ollama service started but not responding yet")
            return False

        except FileNotFoundError:
            logger.error(
                "Ollama executable not found. Please install Ollama: https://ollama.com/download"
            )
            return False
        except Exception as e:
            logger.error(f"Failed to start Ollama service: {e}")
            return False

    def _ensure_ollama_running(self):
        if not self._is_ollama_running():
            logger.warning("Ollama service not detected, attempting to start...")
            if not self._start_ollama_service():
                logger.error(
                    "Could not start Ollama automatically. Try a manual start with ollama serve"
                )
                if not self.auto_start:
                    sys.exit(1)
        else:
            logger.info("Ollama service is running")

    def _ensure_model_available(self):
        try:
            self._ollama_module.show(self.model_name)
            # logger.info(f"Model '{self.model_name}' is available")
        except Exception:
            logger.debug(f"Model '{self.model_name}' not found locally")
            self._pull_model()

    def _pull_model(self):
        logger.info(
            f"Pulling model '{self.model_name}'... This may take a few minutes."
        )
        try:
            if not self._is_ollama_running():
                logger.error("Ollama service not running. Cannot pull model.")
                sys.exit(1)

            self._ollama_module.pull(self.model_name)
            logger.info(f"Successfully pulled: '{self.model_name}'")
        except Exception as e:
            logger.error(f"Failed to pull model: {e}")
            logger.info("Ensure Ollama is running, internet is working correctly!")
            sys.exit(1)

    def analyze(self, prompt: str) -> str:
        """This is the ollama prompt calling
        NOTE: The tokens are set to 10000 right now, this should be modified for more flexible usage.
        """

        try:
            response = self._ollama_module.generate(
                model=self.model_name,
                prompt=prompt,
                stream=False,
                options={"temperature": 0.1, "top_p": 0.9, "num_predict": 10000},
            )
            return response["response"].strip()
        except Exception as e:
            logger.error(f"Ollama analysis failed: {e}")
            return ""

    def is_available(self) -> bool:
        return self._is_ollama_running()

    def initialize(self) -> bool:
        return self.is_available()

    def cleanup(self):
        if self.ollama_process:
            try:
                self.ollama_process.terminate()
                self.ollama_process.wait(timeout=5)
            except (ProcessLookupError, TimeoutError, OSError) as e:
                logger.debug(f"Error during cleanup: {e}")
            except Exception as e:
                logger.warning(f"Unexpected error during cleanup: {e}")
