package delivery

import (
	"github.com/mmikhail2001/technopark_security_hw_proxy/proxy-server/internal/domain"
)

type Repository interface {
	GetAll() ([]domain.HTTPTransaction, error)
	Add(domain.HTTPTransaction) error
}
