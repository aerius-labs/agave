use {
  std::cmp,
  std::sync::{Arc, RwLock},
  crypto::{
    digest::Digest,
    sha3::Sha3,
  },
  solana_svm::transaction_processing_callback::TransactionProcessingCallback,
  solana_sdk::{
    account::{AccountSharedData, ReadableAccount, WritableAccount},
    pubkey::Pubkey,
    native_loader,
},
};

#[derive(Clone)]
pub enum Node<K, V> {
  Leaf {
    key: K,
    value: V,
    version: u32,
    hash: Option<[u8; 32]>,
  },
  Inner {
    left: Option<Box<Node<K, V>>>,
    right: Option<Box<Node<K, V>>>,
    key: K,
    hash: Option<[u8; 32]>,
    height: u8,
    version: u32,
  },
}

#[derive(Clone)]
pub struct IAVL<K, V> {
  pub root:  Arc<RwLock<Option<Box<Node<K, V>>>>>,
  pub version: u32,
}

impl<K, V> Node<K, V> {
  pub fn print(&self)
  where
    K: std::fmt::Display,
    V: std::fmt::Display,
  {
    match self {
      Node::Leaf { key, value, .. } => {
        println!("Leaf: {} {}", key, value);
      }
      Node::Inner {
        key,
        left,
        right,
        height,
        ..
      } => {
        println!("Inner: key: {}, height: {}", key, height);
        match left {
          Some(l) => {
            println!("LEFT:");
            l.print();
          }
          None => {}
        }
        match right {
          Some(r) => {
            println!("RIGHT:");
            r.print()
          }
          None => {}
        }
      }
    }
  }

  fn new_leaf(key: K, value: V, version: u32) -> Self {
    Node::Leaf {
      key: key,
      value: value,
      hash: None,
      version: version,
    }
  }
  fn new_inner(key: K, left: Box<Node<K, V>>, right: Box<Node<K, V>>, version: u32) -> Node<K, V> {
    Node::Inner {
      key: key,
      left: Some(left),
      right: Some(right),
      hash: None,
      height: 1,
      version: version,
    }
  }

  fn insert_in_child(
    root: Option<Box<Node<K, V>>>,
    new_key: K,
    new_value: V,
    version: u32,
  ) -> Option<Box<Node<K, V>>>
  where
    K: Ord + Copy,
  {
    Some(match root {
      Some(node) => Node::insert(node, new_key, new_value, version),
      None => Box::new(Node::new_leaf(new_key, new_value, version)),
    })
  }

  pub fn insert(
    mut root: Box<Node<K, V>>,
    new_key: K,
    new_value: V,
    version: u32,
  ) -> Box<Node<K, V>>
  where
    K: Ord + Copy,
  {
    match *root {
      Node::Inner {
        key,
        ref mut right,
        ref mut left,
        ..
      } => {
        if new_key < key {
          *left = Node::insert_in_child(left.take(), new_key, new_value, version)
        } else {
          *right = Node::insert_in_child(right.take(), new_key, new_value, version)
        }
      }
      Node::Leaf { key, .. } => {
        if new_key < key {
          root = Box::new(Node::new_inner(
            key,
            Box::new(Node::new_leaf(new_key, new_value, version)),
            root,
            version,
          ));
        } else {
          root = Box::new(Node::new_inner(
            new_key,
            root,
            Box::new(Node::new_leaf(new_key, new_value, version)),
            version,
          ));
        }
      }
    }
    Node::update_height(&mut root);
    Node::balance(root)
  }

  pub fn height(root: &Option<Box<Node<K, V>>>) -> u8 {
    match root {
      Some(node) => match node.as_ref() {
        Node::Inner { height, .. } => *height,
        Node::Leaf { .. } => 0,
      },
      None => 0,
    }
  }

  fn update_height(root: &mut Box<Node<K, V>>) {
    match root.as_mut() {
      Node::Inner {
        ref left,
        ref right,
        ref mut height,
        ..
      } => {
        *height = cmp::max(Node::height(left), Node::height(right)) + 1;
      }
      Node::Leaf { .. } => {}
    }
  }

  pub fn update_hash(root: &mut Box<Node<K, V>>) -> [u8; 32] {
    match root.as_mut() {
      Node::Leaf { hash, .. } => {
        // update hash
        let h = [0; 32];
        *hash = Some(h);
        h
      }
      Node::Inner {
        ref mut left,
        ref mut right,
        hash,
        ..
      } => {
        let h_left = match left.as_mut() {
          Some(node) => Node::update_hash(node),
          None => [0; 32],
        };
        let h_right = match right.as_mut() {
          Some(node) => Node::update_hash(node),
          None => [0; 32],
        };
        let mut hasher = Sha3::sha3_256();
        hasher.input(&h_left);
        hasher.input(&h_right);
        let mut h: [u8; 32] = [0; 32];
        hasher.result(&mut h);
        *hash = Some(h);
        h
      }
    }
  }

  fn rotate_right(mut root: Box<Node<K, V>>) -> Box<Node<K, V>> {
    match *root {
      Node::Leaf { .. } => unreachable!("Should not rotate leaf"),
      Node::Inner {
        left: ref mut root_left,
        ..
      } => {
        let mut r = root_left.take().unwrap();
        match r.as_mut() {
          Node::Leaf { .. } => unreachable!("Broken algorithm"),
          Node::Inner { ref mut right, .. } => {
            *root_left = right.take();
            Node::update_height(&mut root);
            *right = Some(root);
            Node::update_height(&mut r);
          }
        }
        return r;
      }
    }
  }

  fn rotate_right_left(mut root: Box<Node<K, V>>) -> Box<Node<K, V>> {
    match *root {
      Node::Leaf { .. } => unreachable!("Should not rotate leaf"),
      Node::Inner {
        right: ref mut root_right,
        ..
      } => {
        let mut r = root_right.take().unwrap();
        match r.as_mut() {
          Node::Leaf { .. } => unreachable!("Broken algorithm"),
          Node::Inner { right, left, .. } => {
            if Node::get_height(left) > Node::get_height(right) {
              let rotated_root = Node::rotate_right(r);
              *root_right = Some(rotated_root);
              Node::update_height(&mut root);
            } else {
              // Give back from take
              *root_right = Some(r);
            }
          }
        }
        Node::rotate_left(root)
      }
    }
  }

  fn rotate_left(mut root: Box<Node<K, V>>) -> Box<Node<K, V>> {
    match *root {
      Node::Leaf { .. } => unreachable!("Should not rotate leaf"),
      Node::Inner {
        right: ref mut root_right,
        ..
      } => {
        let mut r = root_right.take().unwrap();
        match r.as_mut() {
          Node::Leaf { .. } => unreachable!("Broken algorithm"),
          Node::Inner { ref mut left, .. } => {
            *root_right = left.take();
            Node::update_height(&mut root);
            *left = Some(root);
            Node::update_height(&mut r);
          }
        }
        return r;
      }
    }
  }

  fn rotate_left_right(mut root: Box<Node<K, V>>) -> Box<Node<K, V>> {
    match *root {
      Node::Leaf { .. } => unreachable!("Should not rotate leaf"),
      Node::Inner {
        left: ref mut root_left,
        ..
      } => {
        let mut l = root_left.take().unwrap();
        match l.as_mut() {
          Node::Leaf { .. } => unreachable!("Broken algorithm"),
          Node::Inner { left, right, .. } => {
            if Node::get_height(right) > Node::get_height(left) {
              let rotated_root = Node::rotate_left(l);
              *root_left = Some(rotated_root);
              Node::update_height(&mut root);
            } else {
              // Give back from take
              *root_left = Some(l);
            }
          }
        }
        Node::rotate_right(root)
      }
    }
  }

  fn get_height(root: &Option<Box<Node<K, V>>>) -> u8 {
    match root.as_ref() {
      None => 0,
      Some(node) => match node.as_ref() {
        Node::Leaf { .. } => 0,
        Node::Inner { height, .. } => *height,
      },
    }
  }

  fn height_difference(root: &Box<Node<K, V>>) -> i8 {
    match root.as_ref() {
      Node::Leaf { .. } => 0,
      Node::Inner { left, right, .. } => {
        let l = Node::get_height(left);
        let r = Node::get_height(right);
        (l as i8) - (r as i8)
      }
    }
  }

  fn balance(root: Box<Node<K, V>>) -> Box<Node<K, V>> {
    let height_diff = Node::height_difference(&root);
    if height_diff >= -1 && height_diff <= 1 {
      return root;
    }
    match height_diff {
      2 => Node::rotate_left_right(root),
      -2 => Node::rotate_right_left(root),
      _ => unreachable!(),
    }
  }
}

impl<'a, K: Ord, V> Node<K, V> {
  pub fn search(search_key: &K, root: &'a Box<Node<K, V>>) -> Option<(&'a K, &'a V)> {
    match root.as_ref() {
      Node::Leaf { key, value, .. } => {
        if key == search_key {
          Some((&key, &value))
        } else {
          None
        }
      }
      Node::Inner {
        key, left, right, ..
      } => {
        if search_key < key {
          left
            .as_ref()
            .map_or(None, |node| Node::search(search_key, node))
        } else {
          right
            .as_ref()
            .map_or(None, |node| Node::search(search_key, node))
        }
      }
    }
  }
}

impl<K, V> IAVL<K, V> {
  // Creates a new IAVL tree with no root and version 0
  pub fn new() -> Self {
      IAVL {
          root: Arc::new(RwLock::new(None)), // Initialize the root with RwLock
          version: 0,
      }
  }

  // Inserts a new key-value pair into the IAVL tree
  pub fn insert(&mut self, new_key: K, new_value: V)
  where
      K: Ord + Copy,
  {
      // Acquire a write lock to modify the root
      let mut root_guard = self.root.write().unwrap();

      match root_guard.take() {
          None => {
              // If the tree is empty, create a new leaf node as the root
              *root_guard = Some(Box::new(Node::new_leaf(new_key, new_value, self.version)));
          }
          Some(root) => {
              // Insert the new key-value pair into the existing tree
              *root_guard = Some(Node::insert(root, new_key, new_value, self.version));
          }
      }
  }

  // Calculates and saves the tree's hash
  pub fn save_tree(&self) -> [u8; 32] {
      // Acquire a read lock to safely access and update the root hash
      let mut root_guard = self.root.write().unwrap();

      match root_guard.as_mut() {
          None => [0; 32], // Return a zeroed hash if the tree is empty
          Some(root) => Node::update_hash(root), // Update and return the hash of the tree
      }
  }
}


impl TransactionProcessingCallback for IAVL<Pubkey, AccountSharedData> {
  // Method to check if the account's owner matches any of the provided owners
  fn account_matches_owners(&self, account: &Pubkey, owners: &[Pubkey]) -> Option<usize> {
    // Acquire a read lock on the RwLock to safely access the root node
    let root_guard = self.root.read().unwrap(); // Locking for read access

    // Safely access the root and perform the search
    if let Some(data) = root_guard
        .as_ref() // Access the Option inside the RwLock
        .and_then(|root| Node::search(account, root))
    {
        // Check if the account has zero lamports (inactive)
        if data.1.lamports() == 0 {
            None
        } else {
            // Check if the owner of the account matches any of the provided owners
            owners.iter().position(|entry| data.1.owner() == entry)
        }
    } else {
        None
    }
}

  // Method to retrieve the shared data of a given account
    fn get_account_shared_data(&self, pubkey: &Pubkey) -> Option<AccountSharedData> {
        // Acquire a read lock on the root to access the data safely
        let root_guard = self.root.read().unwrap(); // Locking for read access

        // Safely access the root and search for the account data
        root_guard
            .as_ref() // Access the Option inside the RwLock
            .and_then(|root| Node::search(pubkey, root)) // Search for the account in the tree
            .map(|(_, account_data)| account_data.clone()) // Clone the found account data
    }


    // The method remains &self, matching the trait signature
    fn add_builtin_account(&self, name: &str, program_id: &Pubkey) {
      // Create the account using the native loader utility
      let account_data = native_loader::create_loadable_account_with_fields(name, (5000, 0));

      // Use a write lock to gain mutable access to self.root
      let mut root = self.root.write().unwrap(); // Using RwLock for safe mutable access

      // Insert the new account into the IAVL tree
      match root.take() {
          Some(existing_root) => {
              // Insert account data into the existing tree
              *root = Some(Node::insert(existing_root, *program_id, account_data, self.version));
          }
          None => {
              // If the tree is empty, create a new root node with the account
              *root = Some(Box::new(Node::new_leaf(*program_id, account_data, self.version)));
          }
      }
  }
}

// #[cfg(test)]
// mod tests {
//   use super::*;

//   #[test]
//   fn construct_tree() {
//     let mut iavl = IAVL::new();
//     iavl.insert(4, 4);
//   }

//   #[test]
//   fn search() {
//     let mut iavl = IAVL::new();
//     for i in 0..10 {
//       iavl.insert(i, i);
//     }
//     let root = &iavl.root.unwrap();
//     let s = Node::search(&11, root);
//     match s {
//       None => {}
//       Some(_) => assert!(false),
//     }
//     let s = Node::search(&4, root);
//     match s {
//       None => assert!(false),
//       Some(_) => {}
//     }
//   }

//   #[test]
//   fn calculate_hash() {
//     let mut iavl = IAVL::new();
//     for i in 0..10 {
//       iavl.insert(i, i);
//     }
//     iavl.save_tree();
//   }
// }
