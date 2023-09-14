package repository

import (
	"context"
	"log"

	"github.com/mmikhail2001/technopark_security_hw_proxy/proxy-server/internal/domain"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

type Repository struct {
	db            *mongo.Client
	reqCollection *mongo.Collection
}

func NewRepository(db *mongo.Client) (Repository, error) {
	coll := db.Database("mitm").Collection("requests")
	// индекс на поле host (оптимизация поиска и сортировки данных)
	_, err := coll.Indexes().CreateOne(context.TODO(), mongo.IndexModel{
		Keys: bson.M{"host": 1},
	})
	if err != nil {
		log.Println("error Indexes CreateOne", err)
		return Repository{}, err
	}
	return Repository{db: db, reqCollection: coll}, nil
}

func (repo *Repository) Add(req domain.HTTPTransaction) error {
	_, err := repo.reqCollection.InsertOne(context.TODO(), req)
	if err != nil {
		log.Println("error insert one", err)
		return err
	}
	return nil
}

func (repo *Repository) GetAll() ([]domain.HTTPTransaction, error) {
	// извлекаем все записи (фильтра нет)
	cur, err := repo.reqCollection.Find(context.TODO(), bson.D{})
	if err != nil {
		log.Println("error Find", err)
		return []domain.HTTPTransaction{}, err
	}
	defer cur.Close(context.TODO())

	var results []domain.HTTPTransaction
	for cur.Next(context.TODO()) {
		var result domain.HTTPTransaction
		err := cur.Decode(&result)
		if err != nil {
			log.Println("error Decode", err)
			continue
		}
		results = append(results, result)
	}
	if err := cur.Err(); err != nil {
		log.Println("error cur.Err", err)
		return []domain.HTTPTransaction{}, err
	}

	return results, nil
}
