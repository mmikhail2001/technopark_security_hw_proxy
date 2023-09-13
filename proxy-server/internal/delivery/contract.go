package delivery

import (
	"github.com/mmikhail2001/technopark_security_hw_proxy/proxy-server/internal/domain"
)

type Repository interface {
	GetAll() ([]domain.Request, error)
	Add(req domain.Request) error
}
