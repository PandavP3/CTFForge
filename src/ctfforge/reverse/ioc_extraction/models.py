"""Small serializable IOC model with occurrence-level provenance."""
from dataclasses import dataclass, field


@dataclass(frozen=True)
class Occurrence:
    source: str
    offset: int
    encoding: str
    original_value: str

    def as_dict(self) -> dict:
        return {"source": self.source, "offset": self.offset, "encoding": self.encoding,
                "original_value": self.original_value}


@dataclass
class IOC:
    type: str
    value: str
    confidence: str
    validation: str = "valid_syntax"
    _original_values: set[str] = field(default_factory=set, repr=False)
    _occurrences: dict[tuple[str, int, str, str], Occurrence] = field(default_factory=dict, repr=False)
    occurrences_truncated: bool = False

    @staticmethod
    def occurrence_key(occurrence: Occurrence) -> tuple[str, int, str, str]:
        return (occurrence.source, occurrence.offset, occurrence.encoding, occurrence.original_value)

    def has_occurrence(self, occurrence: Occurrence) -> bool:
        return self.occurrence_key(occurrence) in self._occurrences

    def add_occurrence(self, occurrence: Occurrence, *, maximum: int) -> bool:
        key = self.occurrence_key(occurrence)
        if key in self._occurrences:
            return False
        if len(self._occurrences) >= maximum:
            self.occurrences_truncated = True
            return False
        self._occurrences[key] = occurrence
        self._original_values.add(occurrence.original_value)
        return True

    def as_dict(self) -> dict:
        return {"type": self.type, "value": self.value,
                "original_value": min(self._original_values) if self._original_values else self.value,
                "confidence": self.confidence, "validation": self.validation,
                "occurrences": [item.as_dict() for item in sorted(
                    self._occurrences.values(), key=lambda item: (item.offset, item.source,
                                                                  item.encoding, item.original_value))],
                "occurrences_truncated": self.occurrences_truncated}
