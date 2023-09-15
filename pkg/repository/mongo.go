package repository

import (
	"context"
	"log"

	"github.com/mmikhail2001/technopark_security_hw_proxy/pkg/domain"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
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
		id, ok := result.ID.(primitive.ObjectID)

		if ok {
			result.ID = id.Hex()
		} else {
			result.ID = "none"
		}

		results = append(results, result)
	}
	if err := cur.Err(); err != nil {
		log.Println("error cur.Err", err)
		return []domain.HTTPTransaction{}, err
	}

	return results, nil
}

func (repo *Repository) GetByID(id string) (domain.HTTPTransaction, error) {

	objectId, err := primitive.ObjectIDFromHex(id)
	if err != nil {
		return domain.HTTPTransaction{}, err
	}

	transaction := domain.HTTPTransaction{}

	result := repo.reqCollection.FindOne(context.Background(), bson.M{"_id": objectId})
	err = result.Decode(&transaction)
	if err != nil {
		return domain.HTTPTransaction{}, err
	}

	return transaction, nil
}
