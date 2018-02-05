DKIM-Signature: v=1; a=ed25519-sha256; c=relaxed/simple; d=kitterman.org; 
 i=@kitterman.org; q=dns/txt; s=ed25519; t=1517847601; 
 h=message-id : date : from : to : subject : date : from : 
 subject; bh=wE7NXSkgnx9PGiavN4OZhJztvkqPDlemV3OGuEnLwNo=; 
 b=sEnnE99Xsjpcqa/cNf8k/KQCEgjJ/4tswIKoNvq2q0fFQL6XBORJ2fQb
 Fvt34Tb4sOxlZtBYu01kEJlmGz4uCw==
Authentication-Results: lists.example.org; arc=none; spf=pass smtp.mfrom=example.com; dmarc=pass
Received: from localhost
Message-ID: <example@example.com>
Date: Mon, 01 Jan 2011 01:02:03 +0400
From: Test User <test@example.com>
To: somebody@example.com
Subject: Testing

This is a test message.
