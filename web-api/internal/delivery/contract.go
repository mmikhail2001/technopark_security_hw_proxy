package delivery

import (
	"github.com/mmikhail2001/technopark_security_hw_proxy/pkg/domain"
)

type Repository interface {
	GetAll() ([]domain.HTTPTransaction, error)
	GetByID(string) (domain.HTTPTransaction, error)
}
