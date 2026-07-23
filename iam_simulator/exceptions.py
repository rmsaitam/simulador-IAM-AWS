"""Exceções customizadas para o simulador IAM AWS."""


class IAMSimulatorError(Exception):
    """Exceção base do simulador."""
    pass


class EntityAlreadyExistsError(IAMSimulatorError):
    """Entidade já existe."""

    def __init__(self, entity_type: str, name: str):
        self.entity_type = entity_type
        self.name = name
        super().__init__(f"{entity_type} '{name}' already exists")


class EntityNotFoundError(IAMSimulatorError):
    """Entidade não encontrada."""

    def __init__(self, entity_type: str, name: str):
        self.entity_type = entity_type
        self.name = name
        super().__init__(f"{entity_type} '{name}' not found")


class AccessDeniedError(IAMSimulatorError):
    """Acesso negado a um recurso."""

    def __init__(self, principal: str, action: str, resource: str):
        self.principal = principal
        self.action = action
        self.resource = resource
        super().__init__(
            f"User: {principal} is not authorized to perform: {action} on resource: {resource}"
        )


class InvalidPolicyDocumentError(IAMSimulatorError):
    """Documento de política inválido."""

    def __init__(self, detail: str):
        super().__init__(f"Invalid policy document: {detail}")


class CircularDependencyError(IAMSimulatorError):
    """Dependência circular detectada."""

    def __init__(self, detail: str):
        super().__init__(f"Circular dependency detected: {detail}")
