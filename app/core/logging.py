"""Configuration du logging structuré en JSON"""

import logging
import json
import sys
from datetime import datetime
from typing import Any, Dict
from pythonjsonlogger import jsonlogger


class CustomJsonFormatter(jsonlogger.JsonFormatter):
    """Formatter JSON personnalisé avec champs additionnels"""
    
    def add_fields(self, log_record: Dict[str, Any], record: logging.LogRecord, message_dict: Dict[str, Any]) -> None:
        """Ajoute des champs personnalisés au log"""
        super().add_fields(log_record, record, message_dict)
        
        # Ajoute timestamp ISO
        log_record['timestamp'] = datetime.utcnow().isoformat() + 'Z'
        
        # Ajoute le niveau de log
        log_record['level'] = record.levelname
        
        # Ajoute le logger name
        log_record['logger'] = record.name
        
        # Ajoute les informations de module/ligne
        log_record['module'] = record.module
        log_record['line_number'] = record.lineno
        
        # Ajoute la fonction
        log_record['function'] = record.funcName
        
        # Ajoute le path complet
        log_record['pathname'] = record.pathname
        
        # Ajoute les informations du processus
        log_record['process_id'] = record.process
        log_record['thread_id'] = record.thread


def configure_logging(log_level: str = "INFO", json_mode: bool = True) -> logging.Logger:
    """
    Configure le logging pour l'application
    
    Args:
        log_level: Niveau de logging (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        json_mode: Si True, utilise le format JSON; sinon format texte simple
    
    Returns:
        Logger configuré
    """
    
    # Crée le logger root
    logger = logging.getLogger()
    logger.setLevel(log_level.upper())
    
    # Supprime les handlers existants
    for handler in logger.handlers[:]:
        logger.removeHandler(handler)
    
    # Crée un handler pour stdout
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(log_level.upper())
    
    if json_mode:
        # Format JSON pour production
        formatter = CustomJsonFormatter(
            '%(timestamp)s %(level)s %(message)s',
            timestamp=True
        )
    else:
        # Format texte simple pour développement
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
    
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    
    return logger


def get_logger(name: str) -> logging.Logger:
    """
    Obtient un logger avec le nom spécifié
    
    Args:
        name: Nom du logger (généralement __name__)
    
    Returns:
        Logger configuré
    """
    return logging.getLogger(name)
