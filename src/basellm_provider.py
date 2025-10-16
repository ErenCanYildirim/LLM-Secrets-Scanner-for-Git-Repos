from abc import ABC, abstractmethod


class BaseLLMProvider(ABC):
    """abstract base class for the LLM"""

    @abstractmethod
    def analyze(self, prompt: str) -> str:
        pass

    @abstractmethod
    def is_available(self) -> bool:
        pass

    @abstractmethod
    def initialize(self) -> bool:
        pass
