package keymgr

import "golang.org/x/crypto/openpgp"

func combine(sources ...KeySource) KeySource {
	return &combinedKeySource{
		sources: sources,
	}
}

type combinedKeySource struct {
	sources []KeySource
}

func (s *combinedKeySource) GetPublicKeyRing() openpgp.EntityList {
	//TODO: merge the list
	for _, this := range s.sources {
		if kr := this.GetPublicKeyRing(); kr != nil {
			return kr
		}
	}
	return nil
}

func (s *combinedKeySource) GetPublicKey(address string) (*openpgp.Entity, error) {
	for _, this := range s.sources {
		if k, _ := this.GetPublicKey(address); k != nil {
			return k, nil
		}
	}

	return nil, nil
}

func (s *combinedKeySource) GetAllPublicKeys(address string) (openpgp.EntityList, error) {
	ret := make(openpgp.EntityList, 0, 10)

	for _, this := range s.sources {
		if ks, err := this.GetAllPublicKeys(address); err != nil {
			ret = append(ret, ks...)
		}
	}

	return ret, nil
}

func (s *combinedKeySource) GetPublicKeyById(keyid uint64) *openpgp.Entity {
	for _, this := range s.sources {
		if k := this.GetPublicKeyById(keyid); k != nil {
			return k
		}
	}

	return nil
}

func (s *combinedKeySource) GetSecretKey(address string) (*openpgp.Entity, error) {
	for _, this := range s.sources {
		if k, _ := this.GetSecretKey(address); k != nil {
			return k, nil
		}
	}

	return nil, nil
}

func (s *combinedKeySource) GetAllSecretKeys(address string) (openpgp.EntityList, error) {
	ret := make(openpgp.EntityList, 0, 10)

	for _, this := range s.sources {
		if ks, err := this.GetAllSecretKeys(address); err != nil {
			ret = append(ret, ks...)
		}
	}

	return ret, nil
}

func (s *combinedKeySource) GetSecretKeyById(keyid uint64) *openpgp.Entity {
	for _, this := range s.sources {
		if k := this.GetSecretKeyById(keyid); k != nil {
			return k
		}
	}

	return nil
}

func (s *combinedKeySource) GetSecretKeyRing() openpgp.EntityList {
	//TODO: merge the list
	for _, this := range s.sources {
		if kr := this.GetSecretKeyRing(); kr != nil {
			return kr
		}
	}
	return nil
}
