<?php

namespace VMelnik\DoctrineEncryptBundle\Subscribers;

use Doctrine\ORM\Events;
use Doctrine\Common\EventSubscriber;
use Doctrine\ORM\Event\LifecycleEventArgs;
use Doctrine\ORM\Event\PreUpdateEventArgs;
use Doctrine\Common\Annotations\Reader;
use \Doctrine\ORM\EntityManager;
use \ReflectionClass;
use Symfony\Component\HttpKernel\Log\LoggerInterface;
use VMelnik\DoctrineEncryptBundle\Encryptors\EncryptorInterface;

/**
 * Doctrine event subscriber which encrypt/decrypt entities
 */
class DoctrineEncryptSubscriber implements EventSubscriber {
    /**
     * Encryptor interface namespace
     */

    const ENCRYPTOR_INTERFACE_NS = 'VMelnik\DoctrineEncryptBundle\Encryptors\EncryptorInterface';

    /**
     * Encrypted annotation full name
     */
    const ENCRYPTED_ANN_NAME = 'VMelnik\DoctrineEncryptBundle\Configuration\Encrypted';

    /**
     * Encryptor
     * @var EncryptorInterface
     */
    private $encryptor;

    /**
     * @var LoggerInterface
     */
    protected $logger;

    /**
     * Annotation reader
     * @var Doctrine\Common\Annotations\Reader
     */
    private $annReader;

    /**
     * @var boolean
     */
    private $encryptionDisabled = false;

    /**
     * @var boolean
     */
    private $debug = false;

    /**
     * Registr to avoid multi decode operations for one entity
     * @var array
     */
    public static $decodedRegistry = array();

    /**
     * Capitalize string
     * @param string $word
     * @return string
     */
    public static function capitalize($word) {
        if (is_array($word)) {
            $word = $word[0];
        }

        return str_replace(' ', '', ucwords(str_replace(array('-', '_'), ' ', $word)));
    }

    /**
     * Check if we have entity in decoded registry
     * @param Object $entity Some doctrine entity
     * @param \Doctrine\ORM\EntityManager $em
     * @return boolean
     */
    public static function hasInDecodedRegistry($entity, EntityManager $em) {
        $className = get_class($entity);
        $metadata = $em->getClassMetadata($className);
        $getter = 'get' . self::capitalize($metadata->getIdentifier());

        return isset(self::$decodedRegistry[$className][$entity->$getter()]);
    }

    /**
     * Adds entity to decoded registry
     * @param object $entity Some doctrine entity
     * @param \Doctrine\ORM\EntityManager $em
     */
    public static function addToDecodedRegistry($entity, EntityManager $em) {
        $className = get_class($entity);
        $metadata = $em->getClassMetadata($className);
        $getter = 'get' . self::capitalize($metadata->getIdentifier());
        self::$decodedRegistry[$className][$entity->$getter()] = true;
    }

    /**
     * Delete entity from decoded registry
     * @param object $entity Some doctrine entity
     * @param \Doctrine\ORM\EntityManager $em
     */
    public static function removeFromDecodedRegistry($entity, EntityManager $em) {
        $className = get_class($entity);
        $metadata = $em->getClassMetadata($className);
        $getter = 'get' . self::capitalize($metadata->getIdentifier());
        unset(self::$decodedRegistry[$className][$entity->$getter()]);
    }

    /**
     * Initialization of subscriber
     * @param string $encryptorClass  The encryptor class.  This can be empty if
     * a service is being provided.
     * @param string $secretKey The secret key.
     * @param EncryptorInterface|NULL $service (Optional)  An EncryptorInterface.
     * This allows for the use of dependency injection for the encrypters.
     */
    public function __construct(
        LoggerInterface $logger,
        Reader $annReader,
        $encryptorClass,
        $secretKey,
        EncryptorInterface $service = NULL)
    {
        $this->logger = $logger;
        $this->annReader = $annReader;

        if ($service instanceof EncryptorInterface) {
            $this->encryptor = $service;
        } else {
            $this->encryptor = $this->encryptorFactory($encryptorClass, $secretKey);
        }
    }

    private function beginLog($args, $method)
    {
        if (!$this->debug) return;

        $entity = $args->getEntity();
        $em = $args->getEntityManager();
        $entityClass = $this->getEntityClass($entity);
        $entityIdentifier = $this->getEntityIdentifier($entity, $em);

        $this->logger->info('DoctrineEncryptSubscriber::'.$method.' begin {entity_class} {entity_identifier}', array(
            'entity_class'      => $entityClass,
            'entity_identifier' => $entityIdentifier,
        ));
    }

    private function endLog($args, $method)
    {
        if (!$this->debug) return;

        $entity = $args->getEntity();
        $em = $args->getEntityManager();
        $entityClass = $this->getEntityClass($entity);
        $entityIdentifier = $this->getEntityIdentifier($entity, $em);

        $this->logger->info('DoctrineEncryptSubscriber::'.$method.' end {entity_class} {entity_identifier} {decode_registry}', array(
            'entity_class'      => $entityClass,
            'entity_identifier' => $entityIdentifier,
            'decode_registry'   => print_r(self::$decodedRegistry, true),
        ));
    }

    private function getEntityClass($entity)
    {
        $className = get_class($entity);
        return $className;
    }

    private function getEntityIdentifier($entity, EntityManager $em)
    {
        $className = get_class($entity);
        $metadata = $em->getClassMetadata($className);
        $getter = 'get' . self::capitalize($metadata->getIdentifier());

        return $entity->$getter();
    }

    /**
     * Listen a prePersist lifecycle event. Checking and encrypt entities
     * which have @Encrypted annotation
     * @param LifecycleEventArgs $lifecycleEventArgs
     */
    public function prePersist(LifecycleEventArgs $lifecycleEventArgs)
    {
        if ($this->encryptionDisabled) return;

        $this->beginLog($lifecycleEventArgs, 'prePersist');

        // First time the entity is persisted then it has not been decrypted before
        // and it must be encrypted before being inserted in database, even if it is is not in decodedRegistry
        $forceEncryptOperation = true;

        $this->encryptFields($lifecycleEventArgs, null, $forceEncryptOperation);

        $this->endLog($lifecycleEventArgs, 'prePersist');
    }

    /**
     * Listen a preUpdate lifecycle event. Checking and encrypt entities fields
     * which have @Encrypted annotation. Using changesets to avoid preUpdate event
     * restrictions
     * @param PreUpdateEventArgs $preUpdateEventArgs
     */
    public function preUpdate(PreUpdateEventArgs $preUpdateEventArgs)
    {
        if ($this->encryptionDisabled) return;

        $this->beginLog($preUpdateEventArgs, 'preUpdate');

        $this->encryptFields(null, $preUpdateEventArgs);

        $this->endLog($preUpdateEventArgs, 'preUpdate');
    }

    /**
     * Listen a postLoad lifecycle event. Checking and decrypt entities
     * which have @Encrypted annotations
     * @param LifecycleEventArgs $lifecycleEventArgs
     */
    public function postLoad(LifecycleEventArgs $lifecycleEventArgs)
    {
        if ($this->encryptionDisabled) return;

        $this->beginLog($lifecycleEventArgs, 'postLoad');

        $this->decryptFields($lifecycleEventArgs, null);

        $this->endLog($lifecycleEventArgs, 'postLoad');
    }

    public function postUpdate(LifecycleEventArgs $lifecycleEventArgs)
    {
        if ($this->encryptionDisabled) return;

        $this->beginLog($lifecycleEventArgs, 'postUpdate');

        $this->decryptFields($lifecycleEventArgs, null);

        $this->endLog($lifecycleEventArgs, 'postUpdate');
    }

    public function postPersist(LifecycleEventArgs $lifecycleEventArgs)
    {
        if ($this->encryptionDisabled) return;

        $this->beginLog($lifecycleEventArgs, 'postPersist');

        $this->decryptFields($lifecycleEventArgs, null);

        $this->endLog($lifecycleEventArgs, 'postPersist');
    }

    /**
     * Realization of EventSubscriber interface method.
     * @return Array Return all events which this subscriber is listening
     */
    public function getSubscribedEvents() {
        return array(
            Events::prePersist,
            Events::preUpdate,
            Events::postLoad,
            Events::postUpdate,
            Events::postPersist,
        );
    }

    private function processFields($lifecycleEventArgs, $preUpdateEventArgs, $isEncryptOperation, $forceEncryptOperation=false)
    {
        if ($this->encryptionDisabled) return;

        $preUpdateEvent = false;

        if (!is_null($lifecycleEventArgs)) {
            $entity = $lifecycleEventArgs->getEntity();
            $em = $lifecycleEventArgs->getEntityManager();
        }

        if (!is_null($preUpdateEventArgs)) {
            $entity = $preUpdateEventArgs->getEntity();
            $em = $preUpdateEventArgs->getEntityManager();
            $preUpdateEvent = true;
        }

        if (!$forceEncryptOperation) {

            // Entity already encrypted
            if ($isEncryptOperation && $this->isEncrypted($entity, $em)) return;

            // Entity already decrypted
            if (!$isEncryptOperation && !$this->isEncrypted($entity, $em)) return;
        }

        $encryptorMethod = $isEncryptOperation ? 'encrypt' : 'decrypt';
        $reflectionClass = new ReflectionClass($entity);
        $properties = $reflectionClass->getProperties();
        $withAnnotation = false;  // Return if current entity has or not the annotation in any of its properties

        // TODO: add a method to the entity or interface to avoid iterate all properties
        foreach ($properties as $refProperty) {

            // Is this a encrypted property?
            if ($this->annReader->getPropertyAnnotation($refProperty, self::ENCRYPTED_ANN_NAME)) {

                $withAnnotation = true;

                // we have annotation and if it decrypt operation, we must avoid duble decryption
                $propName = $refProperty->getName();

                $methodName = self::capitalize($propName);

                if ($reflectionClass->hasMethod($getter = 'get' . $methodName) && $reflectionClass->hasMethod($setter = 'set' . $methodName)) {

                    // encrypt/decrypt property value
                    if ($preUpdateEvent) {
                        $currentPropValue = $preUpdateEventArgs->getNewValue($propName);
                    } else {
                        $currentPropValue = $entity->$getter();
                    }

                    // encrypt/decrypt property value
                    $newPropValue = $this->encryptor->$encryptorMethod($currentPropValue);

                    if (is_null($newPropValue))  {
                        $this->logger->error('DoctrineEncryptSubscriber::processFields '.$encryptorMethod.' null value {prop_name} {current_value} {new_value}', array(
                            'prop_name'     => $propName,
                            'current_value' => $currentPropValue,
                            'new_value'     => $newPropValue,
                        ));
                    }

                    // Set new property value
                    if ($preUpdateEvent) {
                        $preUpdateEventArgs->setNewValue($propName, $newPropValue);
                    }
                    $entity->$setter($newPropValue);

                    if ($isEncryptOperation) {
                        self::removeFromDecodedRegistry($entity, $em);
                    } else {
                        self::addToDecodedRegistry($entity, $em);
                    }

                    //if ($this->debug)  {
                    $this->logger->info('DoctrineEncryptSubscriber::processFields '.$encryptorMethod.' {prop_name} {current_value} {new_value}', array(
                        'prop_name'     => $propName,
                        'current_value' => $currentPropValue,
                        'new_value'     => $newPropValue,
                    ));
                    //}                 

                } else {
                    throw new \RuntimeException(sprintf("Property %s doesn't has getter/setter", $propName));
                }
            }
        }

        return $withAnnotation;
    }

    private function encryptFields($lifecycleEventArgs, $preUpdateEventArgs, $forceEncryptOperation=false)
    {
        $this->processFields($lifecycleEventArgs, $preUpdateEventArgs, true, $forceEncryptOperation);
    }

    private function decryptFields($lifecycleEventArgs, $preUpdateEventArgs)
    {
        $this->processFields($lifecycleEventArgs, $preUpdateEventArgs, false);
    }

    /**
     * Encryptor factory. Checks and create needed encryptor
     * @param string $classFullName Encryptor namespace and name
     * @param string $secretKey Secret key for encryptor
     * @return EncryptorInterface
     * @throws \RuntimeException
     */
    private function encryptorFactory($classFullName, $secretKey) {
        $refClass = new \ReflectionClass($classFullName);
        if ($refClass->implementsInterface(self::ENCRYPTOR_INTERFACE_NS)) {
            return new $classFullName($secretKey);
        } else {
            throw new \RuntimeException('Encryptor must implements interface EncryptorInterface');
        }
    }

    private function isEncrypted($entity, EntityManager $em) {
        return !$this->isDecrypted($entity, $em);
    }

    private function isDecrypted($entity, EntityManager $em) {
        return self::hasInDecodedRegistry($entity, $em);
    }

}
